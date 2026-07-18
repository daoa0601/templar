import { isSourceSnapshotId } from "./contracts.js";
import { TemplarError, invalidInput } from "./errors.js";
import { buildSourceSurface } from "./source.js";
import type { SourceSnapshot, SourceSurface } from "./source.js";

export const SOURCE_FIX_CHECKS = [
  "patch_scope",
  "finding_coverage",
  "regression_test_coverage",
  "static_review",
] as const;

export interface SourceFixLocation {
  readonly path: string;
  readonly line: number;
}

export interface SourceFixFlowStep extends SourceFixLocation {
  readonly description: string;
}

export interface SourceFixFinding {
  readonly finding_id: string;
  readonly title: string;
  readonly cwe: string;
  readonly severity: "critical" | "high" | "medium" | "low";
  readonly confidence: "high" | "medium";
  readonly primary_location: SourceFixLocation;
  readonly data_flow: ReadonlyArray<SourceFixFlowStep>;
  readonly attack: string;
  readonly impact: string;
  readonly fix_strategy: string;
}

export interface SourceFixContext {
  readonly schema_version: "1";
  readonly source_audit_run_id: string;
  readonly source_snapshot_id: string;
  readonly repository: SourceSnapshot["repository"];
  readonly findings: ReadonlyArray<SourceFixFinding>;
  readonly required_finding_ids: ReadonlyArray<string>;
  readonly original_file_paths: ReadonlyArray<string>;
  readonly evaluator_checks: typeof SOURCE_FIX_CHECKS;
  readonly required_promotion_impact: "high" | "routine";
  readonly dynamic_validation: {
    readonly candidate_must_report: "not_run";
    readonly execution_boundary: "drone_registered_operation_only";
  };
}

export interface SourceAuditReference {
  readonly schema_version: "1";
  readonly source_snapshot_id: string;
  readonly repository: SourceSnapshot["repository"];
}

type UnknownRecord = Readonly<Record<string, unknown>>;

function record(value: unknown, label: string): UnknownRecord {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw invalidInput(`${label} must be an object.`);
  }
  return value as UnknownRecord;
}

function exactKeys(value: UnknownRecord, expected: ReadonlyArray<string>, label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw invalidInput(`${label} does not match its strict schema.`);
  }
}

function text(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string") throw invalidInput(`${label} must be a string.`);
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > maximum ||
    normalized.includes(String.fromCharCode(0))
  ) {
    throw invalidInput(`${label} must contain 1-${maximum} safe characters.`);
  }
  return normalized;
}

function sourceLocation(
  value: unknown,
  label: string,
  linesByPath: ReadonlyMap<string, number>,
): SourceFixLocation {
  const location = record(value, label);
  exactKeys(location, ["path", "line"], label);
  const sourcePath = text(location.path, `${label}.path`, 240);
  const maximumLine = linesByPath.get(sourcePath);
  if (
    maximumLine === undefined ||
    !Number.isSafeInteger(location.line) ||
    (location.line as number) < 1 ||
    (location.line as number) > maximumLine
  ) {
    throw invalidInput(`${label} is outside the original source snapshot.`);
  }
  return { path: sourcePath, line: location.line as number };
}

export function decodeSourceAuditReference(value: unknown): SourceAuditReference {
  const reference = record(value, "source audit reference");
  exactKeys(
    reference,
    ["schema_version", "source_snapshot_id", "repository"],
    "source audit reference",
  );
  if (reference.schema_version !== "1")
    throw invalidInput("Source audit reference version is invalid.");
  if (
    typeof reference.source_snapshot_id !== "string" ||
    !isSourceSnapshotId(reference.source_snapshot_id)
  ) {
    throw invalidInput("Source audit reference has an invalid snapshot ID.");
  }
  const repository = record(reference.repository, "source audit repository");
  const allowedRepositoryKeys = repository.revision === undefined ? ["name"] : ["name", "revision"];
  exactKeys(repository, allowedRepositoryKeys, "source audit repository");
  const name = text(repository.name, "source audit repository.name", 128);
  const revision =
    repository.revision === undefined
      ? undefined
      : text(repository.revision, "source audit repository.revision", 128);
  return {
    schema_version: "1",
    source_snapshot_id: reference.source_snapshot_id,
    repository: { name, ...(revision === undefined ? {} : { revision }) },
  };
}

function fixFinding(
  value: unknown,
  index: number,
  linesByPath: ReadonlyMap<string, number>,
): SourceFixFinding {
  const label = `audit findings[${index}]`;
  const finding = record(value, label);
  exactKeys(
    finding,
    [
      "finding_id",
      "title",
      "cwe",
      "severity",
      "confidence",
      "primary_location",
      "entry_point_hint_ids",
      "input_hint_ids",
      "sink_hint_ids",
      "data_flow",
      "gates",
      "attack",
      "impact",
      "fix_strategy",
    ],
    label,
  );
  const findingId = text(finding.finding_id, `${label}.finding_id`, 64);
  if (!/^FINDING-[0-9]{3,5}$/u.test(findingId))
    throw invalidInput(`${label}.finding_id is invalid.`);
  const cwe = text(finding.cwe, `${label}.cwe`, 16);
  if (!/^CWE-[1-9][0-9]{0,4}$/u.test(cwe)) throw invalidInput(`${label}.cwe is invalid.`);
  if (!["critical", "high", "medium", "low"].includes(String(finding.severity))) {
    throw invalidInput(`${label}.severity is invalid.`);
  }
  if (finding.confidence !== "high" && finding.confidence !== "medium") {
    throw invalidInput(`${label}.confidence is invalid.`);
  }
  if (
    !Array.isArray(finding.data_flow) ||
    finding.data_flow.length === 0 ||
    finding.data_flow.length > 64
  ) {
    throw invalidInput(`${label}.data_flow must contain 1-64 entries.`);
  }
  const dataFlow = finding.data_flow.map((rawStep, stepIndex) => {
    const stepLabel = `${label}.data_flow[${stepIndex}]`;
    const step = record(rawStep, stepLabel);
    exactKeys(step, ["path", "line", "description"], stepLabel);
    return {
      ...sourceLocation({ path: step.path, line: step.line }, stepLabel, linesByPath),
      description: text(step.description, `${stepLabel}.description`, 2_000),
    };
  });
  return {
    finding_id: findingId,
    title: text(finding.title, `${label}.title`, 300),
    cwe,
    severity: finding.severity as SourceFixFinding["severity"],
    confidence: finding.confidence,
    primary_location: sourceLocation(
      finding.primary_location,
      `${label}.primary_location`,
      linesByPath,
    ),
    data_flow: dataFlow,
    attack: text(finding.attack, `${label}.attack`, 4_000),
    impact: text(finding.impact, `${label}.impact`, 4_000),
    fix_strategy: text(finding.fix_strategy, `${label}.fix_strategy`, 4_000),
  };
}

export function buildSourceFixContext(options: {
  readonly sourceAuditRunId: string;
  readonly sourceSnapshotId: string;
  readonly snapshot: SourceSnapshot;
  readonly auditResult: unknown;
  readonly surface?: SourceSurface;
}): SourceFixContext {
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u.test(options.sourceAuditRunId)) {
    throw invalidInput("sourceAuditRunId is invalid.");
  }
  if (!isSourceSnapshotId(options.sourceSnapshotId)) {
    throw invalidInput("sourceSnapshotId is invalid.");
  }
  const result = record(options.auditResult, "accepted source audit result");
  if (
    result.schema_version !== "1" ||
    result.status !== "completed" ||
    !Array.isArray(result.findings)
  ) {
    throw invalidInput("Accepted source audit result is invalid.");
  }
  if (result.findings.length === 0) {
    throw new TemplarError({
      code: "CONFLICT",
      message: "The accepted source audit contains no findings to fix.",
      status: 409,
    });
  }
  if (result.findings.length > 512)
    throw invalidInput("Accepted source audit has too many findings.");

  const surface = options.surface ?? buildSourceSurface(options.snapshot);
  const linesByPath = new Map(
    surface.files.filter((file) => file.in_scope).map((file) => [file.path, file.line_count]),
  );
  const findings = result.findings.map((value, index) => fixFinding(value, index, linesByPath));
  const findingIds = findings.map((finding) => finding.finding_id);
  if (new Set(findingIds).size !== findingIds.length) {
    throw invalidInput("Accepted source audit contains duplicate finding IDs.");
  }
  return {
    schema_version: "1",
    source_audit_run_id: options.sourceAuditRunId,
    source_snapshot_id: options.sourceSnapshotId,
    repository: options.snapshot.repository,
    findings,
    required_finding_ids: findingIds,
    original_file_paths: options.snapshot.files.map((file) => file.path),
    evaluator_checks: SOURCE_FIX_CHECKS,
    required_promotion_impact: findings.some(
      (finding) => finding.severity === "critical" || finding.severity === "high",
    )
      ? "high"
      : "routine",
    dynamic_validation: {
      candidate_must_report: "not_run",
      execution_boundary: "drone_registered_operation_only",
    },
  };
}
