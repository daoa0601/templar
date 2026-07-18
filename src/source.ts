import { createHash } from "node:crypto";
import path from "node:path";

import { Schema, SchemaParser } from "effect";

import { TemplarError, invalidInput } from "./errors.js";

export const MAX_SOURCE_FILES = 1_000;
export const MAX_SOURCE_FILE_BYTES = 512 * 1024;
export const MAX_SOURCE_CONTENT_BYTES = 6 * 1024 * 1024;
export const MAX_SOURCE_HINTS_PER_KIND = 10_000;

const SourceFileSchema = Schema.Struct({
  path: Schema.String,
  content: Schema.String,
});

const SourceSnapshotSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  repository: Schema.Struct({
    name: Schema.String,
    revision: Schema.optionalKey(Schema.String),
  }),
  files: Schema.Array(SourceFileSchema),
});

const decodeSnapshotShape = SchemaParser.decodeUnknownSync(SourceSnapshotSchema, {
  errors: "all",
  onExcessProperty: "error",
});

const SAFE_REPOSITORY_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const SAFE_REVISION = /^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,127}$/u;
const WINDOWS_RESERVED = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
const PORTABLE_PATH_FORBIDDEN = /[<>:"|?*\\]/u;

export interface SourceFile {
  readonly path: string;
  readonly content: string;
}

export interface SourceSnapshot {
  readonly schema_version: "1";
  readonly repository: {
    readonly name: string;
    readonly revision?: string;
  };
  readonly files: ReadonlyArray<SourceFile>;
}

export type SourceFileExclusion =
  | "dependency"
  | "generated_or_build_output"
  | "test_or_fixture"
  | "documentation"
  | "unsupported_text";

export interface SourceSurfaceFile {
  readonly path: string;
  readonly sha256: string;
  readonly byte_count: number;
  readonly line_count: number;
  readonly in_scope: boolean;
  readonly exclusion_reason?: SourceFileExclusion;
}

export interface SourceSurfaceHint {
  readonly hint_id: string;
  readonly kind: string;
  readonly path: string;
  readonly line: number;
  readonly excerpt: string;
}

export interface SourceSurface {
  readonly schema_version: "1";
  readonly analyzer: {
    readonly analyzer_id: "templar.lexical_security_surface";
    readonly version: "1";
    readonly interpretation: "review_leads_not_findings";
  };
  readonly files: ReadonlyArray<SourceSurfaceFile>;
  readonly entry_points: ReadonlyArray<SourceSurfaceHint>;
  readonly input_hints: ReadonlyArray<SourceSurfaceHint>;
  readonly sink_hints: ReadonlyArray<SourceSurfaceHint>;
  readonly available_checks: ReadonlyArray<
    "surface_index" | "full_file_coverage" | "adversarial_falsification"
  >;
}

interface HintPattern {
  readonly kind: string;
  readonly pattern: RegExp;
}

const ENTRY_POINT_PATTERNS: ReadonlyArray<HintPattern> = [
  {
    kind: "http_route",
    pattern:
      /\b(?:app|router|server)\s*\.\s*(?:all|delete|get|head|options|patch|post|put|use)\s*\(/iu,
  },
  {
    kind: "http_route_decorator",
    pattern:
      /@\s*(?:app|router)\s*\.\s*(?:delete|get|patch|post|put|route)\s*\(|@(?:Delete|Get|Patch|Post|Put|Request)Mapping\b/u,
  },
  { kind: "go_http_handler", pattern: /\b(?:http\.)?Handle(?:Func)?\s*\(/u },
  {
    kind: "serverless_handler",
    pattern:
      /\b(?:export\s+(?:default\s+)?(?:async\s+)?(?:function\s+)?(?:handler|lambda_handler)|def\s+(?:handler|lambda_handler)\s*\()/u,
  },
  {
    kind: "message_consumer",
    pattern: /\b(?:consume|consumer|onMessage|subscribe)\s*\(/u,
  },
  {
    kind: "cli_entry",
    pattern:
      /\b(?:if\s+__name__\s*==\s*["']__main__["']|func\s+main\s*\(|static\s+void\s+main\s*\(|Command\s*\()/u,
  },
];

const INPUT_PATTERNS: ReadonlyArray<HintPattern> = [
  {
    kind: "http_request_field",
    pattern:
      /\b(?:ctx|req|request)\s*\.\s*(?:body|cookies?|data|files?|headers?|json|params|query|string|url)\b/iu,
  },
  {
    kind: "python_web_input",
    pattern: /\brequest\s*\.\s*(?:args|cookies|data|files|form|get_json|headers|json|values)\b/u,
  },
  {
    kind: "java_web_input",
    pattern:
      /\bget(?:Cookies|Header|Headers|InputStream|Parameter|ParameterMap|ParameterValues|PathInfo|QueryString)\s*\(/u,
  },
  {
    kind: "go_web_input",
    pattern:
      /\b(?:FormValue|PostFormValue)\s*\(|\b(?:r|req)\s*\.\s*(?:Body|Form|Header|PostForm|URL)\b/u,
  },
  {
    kind: "environment_input",
    pattern: /\b(?:Deno\.env|getenv\s*\(|os\.environ|os\.getenv|process\.env|System\.getenv)\b/u,
  },
  {
    kind: "cli_input",
    pattern: /\b(?:Deno\.args|process\.argv|sys\.argv|os\.Args|CommandLine\.args)\b/u,
  },
  {
    kind: "standard_input",
    pattern: /\b(?:process\.stdin|sys\.stdin|System\.in|readline\s*\(|input\s*\()/u,
  },
  {
    kind: "event_payload",
    pattern: /\b(?:event|message|payload)\s*(?:\[|\.)/u,
  },
];

const SINK_PATTERNS: ReadonlyArray<HintPattern> = [
  {
    kind: "command_execution",
    pattern:
      /\b(?:child_process\s*\.|execFile|execSync|os\.system|Runtime\.getRuntime\(\)\.exec|shell_exec|spawnSync|subprocess\.|system\s*\()\b/u,
  },
  {
    kind: "code_execution",
    pattern: /\b(?:eval|Function|vm\.runIn|exec)\s*\(/u,
  },
  {
    kind: "sql_execution",
    pattern: /\b(?:execute|executeQuery|execSQL|query|queryRaw|raw)\s*\(/u,
  },
  {
    kind: "filesystem_access",
    pattern:
      /\b(?:createReadStream|createWriteStream|open|readFile|readFileSync|sendFile|unlink|writeFile|writeFileSync)\s*\(/u,
  },
  {
    kind: "outbound_request",
    pattern:
      /\b(?:axios\s*\.|fetch\s*\(|http\.(?:get|request)\s*\(|requests\.(?:delete|get|patch|post|put)\s*\(|urlopen\s*\()/u,
  },
  {
    kind: "redirect_or_navigation",
    pattern: /\b(?:redirect|redirect_to|sendRedirect)\s*\(|\b(?:location|window\.location)\s*=/u,
  },
  {
    kind: "html_or_template_render",
    pattern:
      /\b(?:dangerouslySetInnerHTML|innerHTML|outerHTML)\b|\b(?:render|render_template|template)\s*\(/u,
  },
  {
    kind: "deserialization",
    pattern: /\b(?:ObjectInputStream|pickle\.loads?|unserialize|yaml\.load)\b/u,
  },
  {
    kind: "dynamic_module_load",
    pattern: /\b(?:import\s*\(|require\s*\()\s*[^"'`]/u,
  },
  {
    kind: "archive_extraction",
    pattern: /\b(?:extractall|unpack_archive|ZipFile|tar\.extract)\b/u,
  },
];

const SOURCE_EXTENSIONS = new Set([
  ".bash",
  ".c",
  ".cc",
  ".conf",
  ".cpp",
  ".cs",
  ".cjs",
  ".env",
  ".go",
  ".h",
  ".hpp",
  ".html",
  ".ini",
  ".java",
  ".js",
  ".json",
  ".jsx",
  ".kt",
  ".kts",
  ".mjs",
  ".php",
  ".properties",
  ".ps1",
  ".py",
  ".rb",
  ".rs",
  ".scala",
  ".sh",
  ".sql",
  ".swift",
  ".tf",
  ".toml",
  ".ts",
  ".tsx",
  ".xml",
  ".yaml",
  ".yml",
  ".zsh",
]);

const SPECIAL_SOURCE_NAMES = new Set([
  ".env",
  "dockerfile",
  "gemfile",
  "makefile",
  "procfile",
  "requirements.txt",
]);

function boundedText(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maximum) {
    throw invalidInput(`${label} must contain 1-${maximum} characters.`);
  }
  if (/\p{Cc}/u.test(normalized)) throw invalidInput(`${label} contains a control character.`);
  return normalized;
}

function isWellFormedUnicode(value: string): boolean {
  return Buffer.from(value, "utf8").toString("utf8") === value;
}

export function normalizeSourcePath(value: string, label = "file path"): string {
  if (value.length === 0 || value.length > 240 || value !== value.trim()) {
    throw invalidInput(`${label} must be a 1-240 character relative portable path.`);
  }
  if (!isWellFormedUnicode(value)) throw invalidInput(`${label} is not well-formed UTF-8 text.`);
  const normalized = value.normalize("NFC");
  if (normalized !== value || path.posix.isAbsolute(normalized) || normalized.startsWith("/")) {
    throw invalidInput(`${label} must be a normalized relative path.`);
  }
  const segments = normalized.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw invalidInput(`${label} contains an empty or traversal segment.`);
  }
  for (const segment of segments) {
    if (
      segment.length > 100 ||
      [...segment].some((character) => {
        const codePoint = character.codePointAt(0) ?? 0;
        return codePoint <= 0x1f || codePoint === 0x7f;
      }) ||
      PORTABLE_PATH_FORBIDDEN.test(segment) ||
      segment.endsWith(".") ||
      segment.endsWith(" ") ||
      WINDOWS_RESERVED.test(segment)
    ) {
      throw invalidInput(`${label} is not portable.`);
    }
    if (segment.toLowerCase() === ".git") throw invalidInput(`${label} must not contain .git.`);
  }
  return normalized;
}

function content(value: string, label: string): string {
  if (value.includes(String.fromCharCode(0))) throw invalidInput(`${label} contains a null byte.`);
  if (!isWellFormedUnicode(value)) throw invalidInput(`${label} is not well-formed UTF-8 text.`);
  const size = Buffer.byteLength(value, "utf8");
  if (size > MAX_SOURCE_FILE_BYTES) {
    throw new TemplarError({
      code: "SOURCE_LIMIT_EXCEEDED",
      message: `${label} exceeds the ${MAX_SOURCE_FILE_BYTES}-byte per-file limit.`,
      status: 413,
    });
  }
  return value;
}

export function decodeSourceSnapshot(value: unknown): SourceSnapshot {
  let input: typeof SourceSnapshotSchema.Type;
  try {
    input = decodeSnapshotShape(value);
  } catch (cause) {
    throw invalidInput("SourceSnapshot v1 does not match the strict schema.", cause);
  }
  if (input.files.length === 0 || input.files.length > MAX_SOURCE_FILES) {
    throw new TemplarError({
      code: "SOURCE_LIMIT_EXCEEDED",
      message: `files must contain 1-${MAX_SOURCE_FILES} entries.`,
      status: 413,
    });
  }

  let totalBytes = 0;
  const files = input.files
    .map((file, index) => {
      const normalizedPath = normalizeSourcePath(file.path, `files[${index}].path`);
      const normalizedContent = content(file.content, `files[${index}].content`);
      totalBytes += Buffer.byteLength(normalizedContent, "utf8");
      return { path: normalizedPath, content: normalizedContent } satisfies SourceFile;
    })
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  if (totalBytes > MAX_SOURCE_CONTENT_BYTES) {
    throw new TemplarError({
      code: "SOURCE_LIMIT_EXCEEDED",
      message: `Source content exceeds the ${MAX_SOURCE_CONTENT_BYTES}-byte limit.`,
      status: 413,
    });
  }

  const folded = files.map((file) => file.path.toLowerCase());
  if (new Set(folded).size !== folded.length) {
    throw invalidInput("files contain duplicate or case-colliding paths.");
  }
  for (let index = 0; index < files.length - 1; index += 1) {
    const current = files[index]!.path.toLowerCase();
    const next = files[index + 1]!.path.toLowerCase();
    if (next.startsWith(`${current}/`)) {
      throw invalidInput(`files contain a file/directory path collision at ${files[index]!.path}.`);
    }
  }

  const name = boundedText(input.repository.name, "repository.name", 128);
  if (!SAFE_REPOSITORY_NAME.test(name)) throw invalidInput("repository.name is invalid.");
  const revision =
    input.repository.revision === undefined
      ? undefined
      : boundedText(input.repository.revision, "repository.revision", 128);
  if (revision !== undefined && !SAFE_REVISION.test(revision)) {
    throw invalidInput("repository.revision is invalid.");
  }

  return {
    schema_version: "1",
    repository: { name, ...(revision === undefined ? {} : { revision }) },
    files,
  };
}

function exclusionFor(filePath: string): SourceFileExclusion | undefined {
  const lower = filePath.toLowerCase();
  const segments = lower.split("/");
  if (segments.some((segment) => ["node_modules", "third_party", "vendor"].includes(segment))) {
    return "dependency";
  }
  if (
    segments.some((segment) =>
      [".cache", ".next", "build", "coverage", "dist", "generated", "out"].includes(segment),
    ) ||
    /(?:\.map|\.min\.(?:css|js)|(?:^|\/)package-lock\.json|(?:^|\/)pnpm-lock\.yaml)$/u.test(lower)
  ) {
    return "generated_or_build_output";
  }
  if (
    segments.some((segment) =>
      [
        "__fixtures__",
        "__tests__",
        "fixture",
        "fixtures",
        "spec",
        "specs",
        "test",
        "tests",
      ].includes(segment),
    ) ||
    /(?:\.(?:spec|test)\.[^.]+|_test\.go|(?:^|\/)test_[^/]+\.py)$/u.test(lower)
  ) {
    return "test_or_fixture";
  }
  if (
    segments.some((segment) => ["doc", "docs", "documentation"].includes(segment)) ||
    /\.(?:md|mdx|rst)$/u.test(lower)
  ) {
    return "documentation";
  }
  const base = path.posix.basename(lower);
  if (!SOURCE_EXTENSIONS.has(path.posix.extname(base)) && !SPECIAL_SOURCE_NAMES.has(base)) {
    return "unsupported_text";
  }
  return undefined;
}

function lines(value: string): ReadonlyArray<string> {
  return value.length === 0 ? [] : value.split(/\r\n|\n|\r/u);
}

function excerpt(value: string): string {
  const collapsed = value.trim().replace(/\s+/gu, " ");
  return collapsed.length <= 240 ? collapsed : `${collapsed.slice(0, 237)}...`;
}

function collectHints(
  files: ReadonlyArray<SourceFile>,
  inScope: ReadonlySet<string>,
  patterns: ReadonlyArray<HintPattern>,
  prefix: "ENTRY" | "INPUT" | "SINK",
): ReadonlyArray<SourceSurfaceHint> {
  const found: Array<Omit<SourceSurfaceHint, "hint_id">> = [];
  for (const file of files) {
    if (!inScope.has(file.path)) continue;
    for (const [lineIndex, sourceLine] of lines(file.content).entries()) {
      const seenKinds = new Set<string>();
      for (const candidate of patterns) {
        if (candidate.pattern.test(sourceLine) && !seenKinds.has(candidate.kind)) {
          seenKinds.add(candidate.kind);
          found.push({
            kind: candidate.kind,
            path: file.path,
            line: lineIndex + 1,
            excerpt: excerpt(sourceLine),
          });
          if (found.length > MAX_SOURCE_HINTS_PER_KIND) {
            throw new TemplarError({
              code: "SOURCE_LIMIT_EXCEEDED",
              message: `${prefix.toLowerCase()} surface exceeds ${MAX_SOURCE_HINTS_PER_KIND} hints.`,
              status: 413,
            });
          }
        }
      }
    }
  }
  return found.map((hint, index) => ({
    hint_id: `${prefix}-${String(index + 1).padStart(5, "0")}`,
    ...hint,
  }));
}

export function buildSourceSurface(snapshot: SourceSnapshot): SourceSurface {
  const files = snapshot.files.map((file) => {
    const exclusionReason = exclusionFor(file.path);
    const sourceLines = lines(file.content);
    return {
      path: file.path,
      sha256: createHash("sha256").update(file.content, "utf8").digest("hex"),
      byte_count: Buffer.byteLength(file.content, "utf8"),
      line_count: sourceLines.length,
      in_scope: exclusionReason === undefined,
      ...(exclusionReason === undefined ? {} : { exclusion_reason: exclusionReason }),
    } satisfies SourceSurfaceFile;
  });
  const inScope = new Set(files.filter((file) => file.in_scope).map((file) => file.path));
  if (inScope.size === 0) throw invalidInput("Source snapshot has no supported production files.");
  return {
    schema_version: "1",
    analyzer: {
      analyzer_id: "templar.lexical_security_surface",
      version: "1",
      interpretation: "review_leads_not_findings",
    },
    files,
    entry_points: collectHints(snapshot.files, inScope, ENTRY_POINT_PATTERNS, "ENTRY"),
    input_hints: collectHints(snapshot.files, inScope, INPUT_PATTERNS, "INPUT"),
    sink_hints: collectHints(snapshot.files, inScope, SINK_PATTERNS, "SINK"),
    available_checks: ["surface_index", "full_file_coverage", "adversarial_falsification"],
  };
}
