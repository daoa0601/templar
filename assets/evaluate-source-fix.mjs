import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";

const workspace = process.cwd();
const failures = [];
const MAX_CHANGED_FILES = 64;
const MAX_CHANGED_FILE_BYTES = 512 * 1024;
const MAX_CHANGED_BYTES = 2 * 1024 * 1024;

function fail(code, detail) {
  failures.push({ code, detail });
}

function object(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail("invalid_schema", `${label} must be an object`);
    return {};
  }
  return value;
}

function exactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    fail("invalid_schema", `${label} keys were ${actual.join(",")}`);
  }
}

function string(value, label, maximum = 4000) {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > maximum) {
    fail("invalid_schema", `${label} must be a bounded non-empty string`);
    return "";
  }
  return value;
}

function strings(value, label, minimum = 0) {
  if (!Array.isArray(value) || value.length < minimum) {
    fail("invalid_schema", `${label} must contain at least ${minimum} entries`);
    return [];
  }
  const result = value.map((entry, index) => string(entry, `${label}[${index}]`, 240));
  if (new Set(result).size !== result.length) fail("invalid_schema", `${label} has duplicates`);
  return result;
}

function sourcePath(value, label) {
  const candidate = string(value, label, 240);
  const windowsReserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/iu;
  const segments = candidate.split("/");
  if (
    candidate !== candidate.trim() ||
    candidate.startsWith("/") ||
    candidate !== candidate.normalize("NFC") ||
    segments.some(
      (segment) =>
        segment.length === 0 ||
        segment.length > 100 ||
        segment === "." ||
        segment === ".." ||
        segment.toLowerCase() === ".git" ||
        /[\u0000-\u001f\u007f<>:"|?*\\]/u.test(segment) ||
        segment.endsWith(".") ||
        segment.endsWith(" ") ||
        windowsReserved.test(segment),
    )
  ) {
    fail("invalid_source_path", candidate);
  }
  return candidate;
}

function testLike(sourcePath) {
  const lower = sourcePath.toLowerCase();
  const segments = lower.split("/");
  return (
    segments.some((segment) => ["__tests__", "spec", "specs", "test", "tests"].includes(segment)) ||
    /(?:\.(?:spec|test)\.[^.]+|_test\.go|(?:^|\/)test_[^/]+\.py)$/u.test(lower)
  );
}

function ratio(found, required) {
  if (required.size === 0) return 1;
  let count = 0;
  for (const item of required) if (found.has(item)) count += 1;
  return count / required.size;
}

let context;
let surface;
let result;
let report = "";
try {
  context = JSON.parse(readFileSync(path.join(workspace, "source-fix-context.json"), "utf8"));
  surface = JSON.parse(readFileSync(path.join(workspace, "source-surface.json"), "utf8"));
  result = JSON.parse(readFileSync(path.join(workspace, "result.json"), "utf8"));
  report = readFileSync(path.join(workspace, "report.md"), "utf8");
} catch (error) {
  fail(
    "invalid_schema",
    `Required input could not be read: ${error instanceof Error ? error.message : "unknown"}`,
  );
  context ??= {};
  surface ??= {};
  result ??= {};
}

if (report.trim().length === 0 || report.length > 128_000) {
  fail("invalid_schema", "report.md must be bounded and non-empty");
}
for (const heading of ["Fix summary", "Finding coverage", "Tests", "Residual risk"]) {
  if (!new RegExp(`^# ${heading}$`, "imu").test(report)) {
    fail("invalid_report", `report.md is missing the ${heading} section`);
  }
}

const requiredFindingIds = new Set(
  Array.isArray(context.required_finding_ids) ? context.required_finding_ids : [],
);
const linesByPath = new Map(
  (Array.isArray(surface.files) ? surface.files : [])
    .filter((file) => file && file.in_scope === true)
    .map((file) => [file.path, file.line_count]),
);

function originalLocation(value, label) {
  const location = object(value, label);
  exactKeys(location, ["path", "line"], label);
  const locationPath = sourcePath(location.path, `${label}.path`);
  const maximum = linesByPath.get(locationPath);
  if (
    !Number.isSafeInteger(location.line) ||
    maximum === undefined ||
    location.line < 1 ||
    location.line > maximum
  ) {
    fail("invalid_original_location", `${locationPath}:${String(location.line)}`);
  }
}

const actualChanges = new Map();
try {
  const status = execFileSync(
    "git",
    ["-c", "core.quotepath=false", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
    { cwd: workspace, encoding: "utf8" },
  );
  for (const record of status.split("\0").filter(Boolean)) {
    if (record.length < 4 || record[2] !== " ") {
      fail("unsupported_git_status", record.slice(0, 16));
      continue;
    }
    const code = record.slice(0, 2);
    const file = record.slice(3);
    if (file === "result.json" || file === "report.md" || file === ".harness-audit/trace.jsonl") {
      continue;
    }
    if (!file.startsWith("target/")) {
      fail("forbidden_file_change", file);
      continue;
    }
    const relative = sourcePath(file.slice("target/".length), "changed target path");
    const changeStatus =
      code === "??" || code.includes("A")
        ? "added"
        : code.includes("D")
          ? "deleted"
          : code.includes("M")
            ? "modified"
            : undefined;
    if (changeStatus === undefined || /[RCU]/u.test(code)) {
      fail("unsupported_git_status", `${code}:${relative}`);
      continue;
    }
    actualChanges.set(relative, changeStatus);
  }
} catch (error) {
  fail(
    "evaluator_error",
    `Unable to inspect candidate files: ${error instanceof Error ? error.message : "unknown"}`,
  );
}
if (actualChanges.size === 0) fail("empty_patch", "A fix must change target source and tests");
if (actualChanges.size > MAX_CHANGED_FILES) {
  fail("patch_too_large", `Patch changes more than ${MAX_CHANGED_FILES} files`);
}

let changedBytes = 0;
for (const [relative, status] of actualChanges) {
  if (status === "deleted") continue;
  try {
    const candidate = path.join(workspace, "target", ...relative.split("/"));
    const info = lstatSync(candidate);
    if (!info.isFile() || info.isSymbolicLink()) {
      fail("invalid_changed_file", `${relative} is not a regular file`);
      continue;
    }
    if (info.size > MAX_CHANGED_FILE_BYTES) {
      fail("patch_too_large", `${relative} exceeds ${MAX_CHANGED_FILE_BYTES} bytes`);
      continue;
    }
    const bytes = readFileSync(candidate);
    changedBytes += bytes.byteLength;
    if (bytes.includes(0) || Buffer.from(bytes.toString("utf8"), "utf8").compare(bytes) !== 0) {
      fail("invalid_changed_file", `${relative} is not well-formed UTF-8 text`);
    }
  } catch (error) {
    fail(
      "invalid_changed_file",
      `${relative}: ${error instanceof Error ? error.message : "unknown"}`,
    );
  }
}
if (changedBytes > MAX_CHANGED_BYTES) {
  fail("patch_too_large", `Changed files exceed ${MAX_CHANGED_BYTES} bytes`);
}

result = object(result, "result");
exactKeys(
  result,
  [
    "schema_version",
    "status",
    "summary",
    "finding_resolutions",
    "changes",
    "tests",
    "dynamic_validation",
    "promotion",
    "external_mutations",
  ],
  "result",
);
if (result.schema_version !== "1") fail("invalid_schema", "schema_version must be 1");
if (result.status !== "completed") fail("incomplete_result", "status must be completed");
string(result.summary, "summary", 2000);

const declaredChanges = new Map();
if (
  !Array.isArray(result.changes) ||
  result.changes.length === 0 ||
  result.changes.length > MAX_CHANGED_FILES
) {
  fail("invalid_schema", `changes must contain 1-${MAX_CHANGED_FILES} entries`);
}
for (const [index, raw] of (Array.isArray(result.changes) ? result.changes : []).entries()) {
  const change = object(raw, `changes[${index}]`);
  exactKeys(change, ["path", "status", "finding_ids", "rationale"], `changes[${index}]`);
  const changePath = sourcePath(change.path, `changes[${index}].path`);
  if (declaredChanges.has(changePath)) fail("duplicate_change", changePath);
  if (!["added", "modified", "deleted"].includes(change.status)) {
    fail("invalid_schema", `changes[${index}].status is invalid`);
  }
  if (actualChanges.get(changePath) !== change.status) {
    fail("patch_manifest_mismatch", changePath);
  }
  const findingIds = strings(change.finding_ids, `changes[${index}].finding_ids`, 1);
  for (const findingId of findingIds) {
    if (!requiredFindingIds.has(findingId)) fail("unknown_finding", findingId);
  }
  string(change.rationale, `changes[${index}].rationale`, 2000);
  declaredChanges.set(changePath, { status: change.status, findingIds: new Set(findingIds) });
}
for (const changedPath of actualChanges.keys()) {
  if (!declaredChanges.has(changedPath)) fail("missing_change_manifest", changedPath);
}

const testPaths = new Set();
const testCoveredFindings = new Set();
if (!Array.isArray(result.tests) || result.tests.length === 0 || result.tests.length > 128) {
  fail("invalid_schema", "tests must contain 1-128 entries");
}
for (const [index, raw] of (Array.isArray(result.tests) ? result.tests : []).entries()) {
  const test = object(raw, `tests[${index}]`);
  exactKeys(test, ["path", "finding_ids", "expected_behavior"], `tests[${index}]`);
  const testPath = sourcePath(test.path, `tests[${index}].path`);
  if (testPaths.has(testPath)) fail("duplicate_test", testPath);
  testPaths.add(testPath);
  if (!testLike(testPath)) fail("invalid_regression_test_path", testPath);
  if (!declaredChanges.has(testPath) || declaredChanges.get(testPath).status === "deleted") {
    fail("unchanged_regression_test", testPath);
  }
  const findingIds = strings(test.finding_ids, `tests[${index}].finding_ids`, 1);
  for (const findingId of findingIds) {
    if (!requiredFindingIds.has(findingId)) fail("unknown_finding", findingId);
    testCoveredFindings.add(findingId);
  }
  const declared = declaredChanges.get(testPath);
  for (const findingId of findingIds) {
    if (declared !== undefined && !declared.findingIds.has(findingId)) {
      fail("patch_finding_link_mismatch", `${testPath}:${findingId}`);
    }
  }
  string(test.expected_behavior, `tests[${index}].expected_behavior`, 2000);
}

const resolvedFindingIds = new Set();
if (!Array.isArray(result.finding_resolutions) || result.finding_resolutions.length === 0) {
  fail("invalid_schema", "finding_resolutions must not be empty");
}
for (const [index, raw] of (Array.isArray(result.finding_resolutions)
  ? result.finding_resolutions
  : []
).entries()) {
  const resolution = object(raw, `finding_resolutions[${index}]`);
  exactKeys(
    resolution,
    [
      "finding_id",
      "root_cause",
      "changed_paths",
      "regression_test_paths",
      "variant_locations",
      "residual_risk",
    ],
    `finding_resolutions[${index}]`,
  );
  const findingId = string(resolution.finding_id, `finding_resolutions[${index}].finding_id`, 64);
  if (!requiredFindingIds.has(findingId)) fail("unknown_finding", findingId);
  if (resolvedFindingIds.has(findingId)) fail("duplicate_finding_resolution", findingId);
  resolvedFindingIds.add(findingId);
  string(resolution.root_cause, `finding_resolutions[${index}].root_cause`);
  const changedPaths = strings(
    resolution.changed_paths,
    `finding_resolutions[${index}].changed_paths`,
    1,
  ).map((value) => sourcePath(value, `finding_resolutions[${index}].changed_paths`));
  for (const changedPath of changedPaths) {
    if (!declaredChanges.has(changedPath)) fail("unknown_changed_path", changedPath);
    else if (!declaredChanges.get(changedPath).findingIds.has(findingId)) {
      fail("patch_finding_link_mismatch", `${changedPath}:${findingId}`);
    }
  }
  if (!changedPaths.some((changedPath) => !testLike(changedPath))) {
    fail("missing_implementation_change", findingId);
  }
  const regressionPaths = strings(
    resolution.regression_test_paths,
    `finding_resolutions[${index}].regression_test_paths`,
    1,
  ).map((value) => sourcePath(value, `finding_resolutions[${index}].regression_test_paths`));
  for (const testPath of regressionPaths) {
    if (!testPaths.has(testPath)) fail("unknown_regression_test", testPath);
    const declared = declaredChanges.get(testPath);
    if (declared !== undefined && !declared.findingIds.has(findingId)) {
      fail("patch_finding_link_mismatch", `${testPath}:${findingId}`);
    }
  }
  if (!Array.isArray(resolution.variant_locations) || resolution.variant_locations.length === 0) {
    fail("invalid_schema", `finding_resolutions[${index}].variant_locations must not be empty`);
  }
  for (const [locationIndex, rawLocation] of (Array.isArray(resolution.variant_locations)
    ? resolution.variant_locations
    : []
  ).entries()) {
    originalLocation(
      rawLocation,
      `finding_resolutions[${index}].variant_locations[${locationIndex}]`,
    );
  }
  string(resolution.residual_risk, `finding_resolutions[${index}].residual_risk`);
}
const usedChangedPaths = new Set();
for (const raw of Array.isArray(result.finding_resolutions) ? result.finding_resolutions : []) {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) continue;
  for (const value of [raw.changed_paths, raw.regression_test_paths]) {
    if (!Array.isArray(value)) continue;
    for (const changedPath of value) {
      if (typeof changedPath === "string") usedChangedPaths.add(changedPath);
    }
  }
}
for (const changedPath of declaredChanges.keys()) {
  if (!usedChangedPaths.has(changedPath)) fail("unlinked_patch_change", changedPath);
}
for (const findingId of requiredFindingIds) {
  if (!resolvedFindingIds.has(findingId)) fail("missing_finding_resolution", findingId);
  if (!testCoveredFindings.has(findingId)) fail("missing_regression_test_coverage", findingId);
}

const dynamicValidation = object(result.dynamic_validation, "dynamic_validation");
exactKeys(dynamicValidation, ["status", "job_id"], "dynamic_validation");
if (dynamicValidation.status !== "not_run" || dynamicValidation.job_id !== null) {
  fail("false_dynamic_validation_claim", "Candidate-side dynamic validation is forbidden");
}
const promotion = object(result.promotion, "promotion");
exactKeys(promotion, ["impact", "security_outcome", "headline_result"], "promotion");
if (promotion.impact !== context.required_promotion_impact) {
  fail("invalid_promotion", "promotion impact does not match accepted findings");
}
if (promotion.security_outcome !== true || promotion.headline_result !== false) {
  fail("invalid_promotion", "source fix promotion flags are fixed");
}
if (!Array.isArray(result.external_mutations) || result.external_mutations.length !== 0) {
  fail("forbidden_external_mutation", "external_mutations must be empty");
}

const coverage = {
  findings: ratio(resolvedFindingIds, requiredFindingIds),
  regression_tests: ratio(testCoveredFindings, requiredFindingIds),
  patch_manifest:
    actualChanges.size === 0
      ? 0
      : ratio(new Set(declaredChanges.keys()), new Set(actualChanges.keys())),
};
const score =
  Math.round(
    (50 * coverage.findings + 30 * coverage.regression_tests + 20 * coverage.patch_manifest) *
      1_000_000,
  ) / 1_000_000;
const hardGateFailures = [
  ...new Map(failures.map((failure) => [`${failure.code}|${failure.detail}`, failure])).values(),
].sort(
  (left, right) => left.code.localeCompare(right.code) || left.detail.localeCompare(right.detail),
);
const evaluation = {
  schema_version: "1",
  evaluator_version: "source-fix-evaluator-v1",
  passed: hardGateFailures.length === 0,
  hard_gate_failures: hardGateFailures,
  coverage,
  score,
};
process.stdout.write(`${JSON.stringify(evaluation)}\n`);
if (!evaluation.passed) process.exitCode = 1;
