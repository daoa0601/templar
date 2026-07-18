import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

const workspace = process.cwd();
const failures = [];

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

function strings(value, label, maximum = 240) {
  if (!Array.isArray(value)) {
    fail("invalid_schema", `${label} must be an array`);
    return [];
  }
  const result = value.map((entry, index) => string(entry, `${label}[${index}]`, maximum));
  if (new Set(result).size !== result.length) fail("invalid_schema", `${label} has duplicates`);
  return result;
}

function ratio(found, required) {
  if (required.size === 0) return 1;
  let present = 0;
  for (const item of required) if (found.has(item)) present += 1;
  return present / required.size;
}

let surface;
let result;
let report = "";
try {
  surface = JSON.parse(readFileSync(path.join(workspace, "source-surface.json"), "utf8"));
  result = JSON.parse(readFileSync(path.join(workspace, "result.json"), "utf8"));
  report = readFileSync(path.join(workspace, "report.md"), "utf8");
} catch (error) {
  fail(
    "invalid_schema",
    `Required input could not be read: ${error instanceof Error ? error.message : "unknown"}`,
  );
  surface ??= {};
  result ??= {};
}

if (report.trim().length === 0 || report.length > 128_000) {
  fail("invalid_schema", "report.md must be bounded and non-empty");
}
for (const heading of [
  "Scope",
  "Attack surface",
  "Confirmed findings",
  "Eliminated candidates",
  "Limitations",
]) {
  if (!new RegExp(`^# ${heading}$`, "imu").test(report)) {
    fail("invalid_report", `report.md is missing the ${heading} section`);
  }
}

const fileLines = new Map(
  (Array.isArray(surface.files) ? surface.files : [])
    .filter((file) => file && file.in_scope === true)
    .map((file) => [file.path, file.line_count]),
);
const requiredFiles = new Set(fileLines.keys());
const entryIds = new Set(
  (Array.isArray(surface.entry_points) ? surface.entry_points : []).map((hint) => hint.hint_id),
);
const inputIds = new Set(
  (Array.isArray(surface.input_hints) ? surface.input_hints : []).map((hint) => hint.hint_id),
);
const sinkIds = new Set(
  (Array.isArray(surface.sink_hints) ? surface.sink_hints : []).map((hint) => hint.hint_id),
);
const availableChecks = new Set(
  Array.isArray(surface.available_checks) ? surface.available_checks : [],
);

function location(value, label) {
  const candidate = object(value, label);
  exactKeys(candidate, ["path", "line"], label);
  const sourcePath = string(candidate.path, `${label}.path`, 240);
  const line = candidate.line;
  if (!fileLines.has(sourcePath)) fail("unknown_location_path", sourcePath);
  if (!Number.isSafeInteger(line) || line < 1 || line > (fileLines.get(sourcePath) ?? 0)) {
    fail("invalid_location_line", `${sourcePath}:${String(line)}`);
  }
}

function dispositions(value, label, known, allowed) {
  if (!Array.isArray(value)) {
    fail("invalid_schema", `${label} must be an array`);
    return new Set();
  }
  const observed = new Set();
  for (const [index, raw] of value.entries()) {
    const item = object(raw, `${label}[${index}]`);
    exactKeys(item, ["hint_id", "disposition", "rationale"], `${label}[${index}]`);
    const hintId = string(item.hint_id, `${label}[${index}].hint_id`, 64);
    if (!known.has(hintId)) fail("unknown_surface_hint", hintId);
    if (observed.has(hintId)) fail("duplicate_surface_disposition", hintId);
    observed.add(hintId);
    if (!allowed.has(item.disposition)) {
      fail("invalid_schema", `${label}[${index}].disposition is invalid`);
    }
    string(item.rationale, `${label}[${index}].rationale`, 2000);
  }
  for (const hintId of known) {
    if (!observed.has(hintId)) fail("missing_surface_disposition", hintId);
  }
  return observed;
}

result = object(result, "result");
exactKeys(
  result,
  [
    "schema_version",
    "status",
    "summary",
    "coverage",
    "findings",
    "eliminated_candidates",
    "checks_performed",
    "promotion",
    "external_mutations",
  ],
  "result",
);
if (result.schema_version !== "1") fail("invalid_schema", "schema_version must be 1");
if (result.status !== "completed") fail("incomplete_result", "status must be completed");
string(result.summary, "summary", 2000);

const coverage = object(result.coverage, "coverage");
exactKeys(
  coverage,
  ["scanned_file_paths", "entry_point_dispositions", "input_dispositions", "sink_dispositions"],
  "coverage",
);
const scannedFiles = new Set(strings(coverage.scanned_file_paths, "coverage.scanned_file_paths"));
for (const sourcePath of scannedFiles) {
  if (!requiredFiles.has(sourcePath)) fail("unknown_scanned_file", sourcePath);
}
for (const sourcePath of requiredFiles) {
  if (!scannedFiles.has(sourcePath)) fail("missing_scanned_file", sourcePath);
}
const coveredEntries = dispositions(
  coverage.entry_point_dispositions,
  "coverage.entry_point_dispositions",
  entryIds,
  new Set(["analyzed", "not_applicable"]),
);
const coveredInputs = dispositions(
  coverage.input_dispositions,
  "coverage.input_dispositions",
  inputIds,
  new Set(["attacker_controlled", "not_attacker_controlled", "not_applicable"]),
);
const coveredSinks = dispositions(
  coverage.sink_dispositions,
  "coverage.sink_dispositions",
  sinkIds,
  new Set(["reachable", "not_reachable", "not_security_relevant", "not_applicable"]),
);

const findingIds = new Set();
let hasHighImpactFinding = false;
if (!Array.isArray(result.findings)) fail("invalid_schema", "findings must be an array");
for (const [index, raw] of (Array.isArray(result.findings) ? result.findings : []).entries()) {
  const finding = object(raw, `findings[${index}]`);
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
    `findings[${index}]`,
  );
  const findingId = string(finding.finding_id, `findings[${index}].finding_id`, 64);
  if (!/^FINDING-[0-9]{3,5}$/u.test(findingId)) fail("invalid_finding_id", findingId);
  if (findingIds.has(findingId)) fail("duplicate_finding", findingId);
  findingIds.add(findingId);
  string(finding.title, `findings[${index}].title`, 300);
  const cwe = string(finding.cwe, `findings[${index}].cwe`, 16);
  if (!/^CWE-[1-9][0-9]{0,4}$/u.test(cwe)) fail("invalid_cwe", cwe);
  if (!["critical", "high", "medium", "low"].includes(finding.severity)) {
    fail("invalid_schema", `findings[${index}].severity is invalid`);
  }
  if (finding.severity === "critical" || finding.severity === "high") {
    hasHighImpactFinding = true;
  }
  if (!["high", "medium"].includes(finding.confidence)) {
    fail("invalid_schema", `findings[${index}].confidence is invalid`);
  }
  location(finding.primary_location, `findings[${index}].primary_location`);
  for (const hintId of strings(
    finding.entry_point_hint_ids,
    `findings[${index}].entry_point_hint_ids`,
    64,
  )) {
    if (!entryIds.has(hintId)) fail("unknown_surface_hint", hintId);
  }
  for (const hintId of strings(finding.input_hint_ids, `findings[${index}].input_hint_ids`, 64)) {
    if (!inputIds.has(hintId)) fail("unknown_surface_hint", hintId);
  }
  for (const hintId of strings(finding.sink_hint_ids, `findings[${index}].sink_hint_ids`, 64)) {
    if (!sinkIds.has(hintId)) fail("unknown_surface_hint", hintId);
  }
  if (!Array.isArray(finding.data_flow) || finding.data_flow.length === 0) {
    fail("invalid_schema", `findings[${index}].data_flow must not be empty`);
  }
  for (const [flowIndex, rawStep] of (Array.isArray(finding.data_flow)
    ? finding.data_flow
    : []
  ).entries()) {
    const step = object(rawStep, `findings[${index}].data_flow[${flowIndex}]`);
    exactKeys(step, ["path", "line", "description"], `findings[${index}].data_flow[${flowIndex}]`);
    location(
      { path: step.path, line: step.line },
      `findings[${index}].data_flow[${flowIndex}].location`,
    );
    string(step.description, `findings[${index}].data_flow[${flowIndex}].description`, 2000);
  }
  const gates = object(finding.gates, `findings[${index}].gates`);
  const gateNames = [
    "unintended_behavior",
    "production_reachability",
    "attacker_control",
    "defense_failure",
    "new_capability",
  ];
  exactKeys(gates, gateNames, `findings[${index}].gates`);
  for (const gateName of gateNames) {
    const gate = object(gates[gateName], `findings[${index}].gates.${gateName}`);
    exactKeys(gate, ["passed", "evidence"], `findings[${index}].gates.${gateName}`);
    if (gate.passed !== true) fail("unproven_finding_gate", `${findingId}:${gateName}`);
    string(gate.evidence, `findings[${index}].gates.${gateName}.evidence`);
  }
  string(finding.attack, `findings[${index}].attack`);
  string(finding.impact, `findings[${index}].impact`);
  string(finding.fix_strategy, `findings[${index}].fix_strategy`);
}

const eliminatedIds = new Set();
if (!Array.isArray(result.eliminated_candidates)) {
  fail("invalid_schema", "eliminated_candidates must be an array");
}
for (const [index, raw] of (Array.isArray(result.eliminated_candidates)
  ? result.eliminated_candidates
  : []
).entries()) {
  const eliminated = object(raw, `eliminated_candidates[${index}]`);
  exactKeys(
    eliminated,
    ["candidate_id", "title", "reason", "evidence_locations"],
    `eliminated_candidates[${index}]`,
  );
  const candidateId = string(
    eliminated.candidate_id,
    `eliminated_candidates[${index}].candidate_id`,
    64,
  );
  if (!/^CANDIDATE-[0-9]{3,5}$/u.test(candidateId)) fail("invalid_candidate_id", candidateId);
  if (eliminatedIds.has(candidateId)) fail("duplicate_eliminated_candidate", candidateId);
  eliminatedIds.add(candidateId);
  string(eliminated.title, `eliminated_candidates[${index}].title`, 300);
  string(eliminated.reason, `eliminated_candidates[${index}].reason`);
  if (!Array.isArray(eliminated.evidence_locations) || eliminated.evidence_locations.length === 0) {
    fail("invalid_schema", `eliminated_candidates[${index}].evidence_locations must not be empty`);
  }
  for (const [locationIndex, rawLocation] of (Array.isArray(eliminated.evidence_locations)
    ? eliminated.evidence_locations
    : []
  ).entries()) {
    location(rawLocation, `eliminated_candidates[${index}].evidence_locations[${locationIndex}]`);
  }
}

const performedChecks = new Set(strings(result.checks_performed, "checks_performed", 64));
for (const check of performedChecks) {
  if (!availableChecks.has(check)) fail("unavailable_check_claim", check);
}
for (const check of availableChecks) {
  if (!performedChecks.has(check)) fail("missing_required_check", check);
}

const promotion = object(result.promotion, "promotion");
exactKeys(promotion, ["impact", "security_outcome", "headline_result"], "promotion");
if (promotion.impact !== "routine" && promotion.impact !== "high") {
  fail("invalid_schema", "promotion.impact is invalid");
}
if (hasHighImpactFinding && promotion.impact !== "high") {
  fail("invalid_promotion", "critical or high findings require high impact promotion");
}
if (promotion.security_outcome !== true || promotion.headline_result !== false) {
  fail("invalid_promotion", "static security audit promotion flags are fixed");
}
if (!Array.isArray(result.external_mutations) || result.external_mutations.length !== 0) {
  fail("forbidden_external_mutation", "external_mutations must be empty");
}

try {
  const changed = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], {
    cwd: workspace,
    encoding: "utf8",
  });
  for (const line of changed.split("\n").filter(Boolean)) {
    const file = line.slice(3).replace(/^.* -> /u, "");
    if (file !== "result.json" && file !== "report.md" && file !== ".harness-audit/trace.jsonl") {
      fail("forbidden_file_change", file);
    }
  }
} catch (error) {
  fail(
    "evaluator_error",
    `Unable to inspect candidate files: ${error instanceof Error ? error.message : "unknown"}`,
  );
}

const coverageRatios = {
  files: ratio(scannedFiles, requiredFiles),
  entry_points: ratio(coveredEntries, entryIds),
  inputs: ratio(coveredInputs, inputIds),
  sinks: ratio(coveredSinks, sinkIds),
  checks: ratio(performedChecks, availableChecks),
};
const score =
  Math.round(
    (40 * coverageRatios.files +
      15 * coverageRatios.entry_points +
      20 * coverageRatios.inputs +
      20 * coverageRatios.sinks +
      5 * coverageRatios.checks) *
      1_000_000,
  ) / 1_000_000;
const hardGateFailures = [
  ...new Map(failures.map((failure) => [`${failure.code}|${failure.detail}`, failure])).values(),
].sort(
  (left, right) => left.code.localeCompare(right.code) || left.detail.localeCompare(right.detail),
);
const evaluation = {
  schema_version: "1",
  evaluator_version: "source-security-evaluator-v1",
  passed: hardGateFailures.length === 0,
  hard_gate_failures: hardGateFailures,
  coverage: coverageRatios,
  score,
};
process.stdout.write(`${JSON.stringify(evaluation)}\n`);
if (!evaluation.passed) process.exitCode = 1;
