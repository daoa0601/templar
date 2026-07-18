import { runBoundedProcess } from "@agentic-orch/node-guardrails";

import { invalidInput } from "./errors.js";

export interface SevenZipMember {
  readonly path: string;
  readonly size: number;
  readonly encrypted: boolean;
  readonly block: string | null;
}

export function sevenZipPasswordStdin(password: string): string {
  if (
    password.length === 0 ||
    password.length > 1024 ||
    password.includes(String.fromCharCode(0)) ||
    /[\r\n]/u.test(password)
  ) {
    throw invalidInput("The 7-Zip password is invalid.");
  }
  return `${password}\n`;
}

export function sevenZipEnvironment(base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const inherited = ["PATH", "TMPDIR", "TEMP", "TMP", "SystemRoot", "ComSpec", "PATHEXT"] as const;
  return {
    ...Object.fromEntries(
      inherited.flatMap((name) => (base[name] === undefined ? [] : [[name, base[name]]])),
    ),
    LANG: "C",
    LC_ALL: "C",
  };
}

export function sevenZipListArgs(archivePath: string): ReadonlyArray<string> {
  return ["l", "-slt", "-ba", "--", archivePath];
}

export function sevenZipExtractToStdoutArgs(
  archivePath: string,
  members: ReadonlyArray<SevenZipMember>,
): ReadonlyArray<string> {
  return ["x", "-so", "--", archivePath, ...members.map(({ path }) => path)];
}

function safeMemberPath(value: string): string {
  if (
    value.length === 0 ||
    value.length > 1024 ||
    value.includes(String.fromCharCode(0)) ||
    value.startsWith("/") ||
    value.startsWith("\\") ||
    /^[a-z]:/iu.test(value)
  ) {
    throw invalidInput("A 7-Zip member has an unsafe path.");
  }
  const segments = value.replaceAll("\\", "/").split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw invalidInput("A 7-Zip member has an unsafe path segment.");
  }
  return value;
}

/** Parse `7zz l -slt -ba` output without trusting member names or numeric fields. */
export function parseSevenZipTechnicalList(text: string): ReadonlyArray<SevenZipMember> {
  if (text.length === 0 || text.length > 4 * 1024 * 1024) {
    throw invalidInput("The 7-Zip technical listing is empty or too large.");
  }
  const members: SevenZipMember[] = [];
  const paths = new Set<string>();
  for (const block of text
    .replaceAll("\r\n", "\n")
    .trim()
    .split(/\n\s*\n/gu)) {
    const fields = new Map<string, string>();
    for (const line of block.split("\n")) {
      const separator = line.indexOf(" =");
      if (separator <= 0) throw invalidInput("The 7-Zip technical listing is malformed.");
      const key = line.slice(0, separator);
      if (fields.has(key)) throw invalidInput(`The 7-Zip listing repeats ${key}.`);
      const valueOffset = line[separator + 2] === " " ? separator + 3 : separator + 2;
      fields.set(key, line.slice(valueOffset));
    }
    const attributes = fields.get("Attributes");
    if (attributes?.includes("D") === true) continue;
    const memberPath = safeMemberPath(fields.get("Path") ?? "");
    if (paths.has(memberPath)) throw invalidInput(`Duplicate 7-Zip member ${memberPath}.`);
    paths.add(memberPath);
    const sizeText = fields.get("Size");
    if (sizeText === undefined || !/^[0-9]+$/u.test(sizeText)) {
      throw invalidInput(`7-Zip member ${memberPath} has an invalid size.`);
    }
    const size = Number(sizeText);
    if (!Number.isSafeInteger(size) || size <= 0) {
      throw invalidInput(`7-Zip member ${memberPath} has an invalid size.`);
    }
    members.push({
      path: memberPath,
      size,
      encrypted: fields.get("Encrypted") === "+",
      block: fields.get("Block") ?? null,
    });
  }
  if (members.length === 0) throw invalidInput("The 7-Zip archive has no regular-file members.");
  return members;
}

export async function listSevenZipMembers(options: {
  readonly executable: string;
  readonly archivePath: string;
  readonly password: string;
  readonly cwd: string;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}): Promise<ReadonlyArray<SevenZipMember>> {
  const result = await runBoundedProcess({
    executable: options.executable,
    args: sevenZipListArgs(options.archivePath),
    cwd: options.cwd,
    env: sevenZipEnvironment(),
    stdin: sevenZipPasswordStdin(options.password),
    timeoutMs: options.timeoutMs ?? 30_000,
    maxOutputBytes: 4 * 1024 * 1024,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (result.exitCode !== 0) throw invalidInput("7-Zip could not list the course archive.");
  return parseSevenZipTechnicalList(
    result.stdout.toString("utf8").replace(/^\s*Enter password:\s*\r?\n/u, ""),
  );
}
