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

function string(value, label, maximum = 4096) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
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
  const values = value.map((entry, index) => string(entry, `${label}[${index}]`, 500));
  if (new Set(values).size !== values.length) fail("invalid_schema", `${label} has duplicates`);
  return values;
}

function ratio(found, required) {
  if (required.size === 0) return 1;
  let present = 0;
  for (const item of required) if (found.has(item)) present += 1;
  return present / required.size;
}

let context;
let result;
let report = "";
try {
  context = JSON.parse(readFileSync(path.join(workspace, "evaluation", "context.json"), "utf8"));
  result = JSON.parse(readFileSync(path.join(workspace, "result.json"), "utf8"));
  report = readFileSync(path.join(workspace, "report.md"), "utf8");
} catch (error) {
  fail(
    "invalid_schema",
    `Required input could not be read: ${error instanceof Error ? error.message : "unknown"}`,
  );
  context ??= {};
  result ??= {};
}

if (report.trim().length === 0 || report.length > 32_000) {
  fail("invalid_schema", "report.md must be bounded and non-empty");
}
for (const heading of ["Observed facts", "Hypotheses", "Defensive next steps"]) {
  if (!new RegExp(`^# ${heading}$`, "imu").test(report)) {
    fail("invalid_report", `report.md is missing the ${heading} section`);
  }
}

result = object(result, "result");
exactKeys(
  result,
  [
    "schema_version",
    "status",
    "summary",
    "assessment",
    "observation_ids",
    "hypotheses",
    "unknown_ids",
    "advisory_action_ids",
    "checks_performed",
    "promotion",
    "external_mutations",
  ],
  "result",
);
if (result.schema_version !== "1") fail("invalid_schema", "schema_version must be 1");
if (result.status !== "completed" && result.status !== "needs_review") {
  fail("invalid_schema", "status is invalid");
}
const summary = string(result.summary, "summary", 2000);
const assessments = new Set([
  "suspicious_needs_review",
  "inconclusive",
  "no_supported_security_conclusion",
]);
if (!assessments.has(result.assessment)) fail("invalid_schema", "assessment is invalid");
if (result.assessment !== "no_supported_security_conclusion" && result.status !== "needs_review") {
  fail("invalid_status", "Suspicious or inconclusive packet triage requires review");
}

const knownObservations = new Set(context.known_observation_ids ?? []);
const observationIds = strings(result.observation_ids, "observation_ids", 1);
for (const id of observationIds) {
  if (!knownObservations.has(id)) fail("unknown_observation", id);
}
const observationSet = new Set(observationIds);
const knownPrinciples = new Set(context.known_principle_ids ?? []);
const knownUnknowns = new Set(context.known_unknown_ids ?? []);
const hypothesisIds = new Set();
const hypothesisText = [];
if (!Array.isArray(result.hypotheses) || result.hypotheses.length === 0) {
  fail("invalid_schema", "hypotheses must contain at least one entry");
}
for (const [index, raw] of (Array.isArray(result.hypotheses) ? result.hypotheses : []).entries()) {
  const hypothesis = object(raw, `hypotheses[${index}]`);
  exactKeys(
    hypothesis,
    [
      "hypothesis_id",
      "statement",
      "confidence",
      "observation_ids",
      "principle_ids",
      "alternatives",
      "unknown_ids",
      "kill_chain_stage",
    ],
    `hypotheses[${index}]`,
  );
  const hypothesisId = string(hypothesis.hypothesis_id, "hypothesis_id", 128);
  if (hypothesisIds.has(hypothesisId)) fail("invalid_schema", `duplicate ${hypothesisId}`);
  hypothesisIds.add(hypothesisId);
  hypothesisText.push(string(hypothesis.statement, "hypothesis.statement", 2000));
  if (hypothesis.confidence !== "low" && hypothesis.confidence !== "moderate") {
    fail("invalid_schema", "hypothesis confidence must be low or moderate");
  }
  if (
    hypothesis.kill_chain_stage !== null &&
    !new Set(["delivery", "command_and_control", "actions_on_objectives"]).has(
      hypothesis.kill_chain_stage,
    )
  ) {
    fail("invalid_schema", "kill_chain_stage is invalid");
  }
  for (const id of strings(hypothesis.observation_ids, "hypothesis.observation_ids", 1)) {
    if (!knownObservations.has(id)) fail("unknown_observation", id);
    if (!observationSet.has(id)) fail("unlisted_observation", id);
  }
  for (const id of strings(hypothesis.principle_ids, "hypothesis.principle_ids", 1)) {
    if (!knownPrinciples.has(id)) fail("unknown_principle", id);
  }
  strings(hypothesis.alternatives, "hypothesis.alternatives", 1);
  for (const id of strings(hypothesis.unknown_ids, "hypothesis.unknown_ids", 1)) {
    if (!knownUnknowns.has(id)) fail("unknown_unknown", id);
  }
}

const unknownIds = strings(result.unknown_ids, "unknown_ids", 1);
for (const id of unknownIds) if (!knownUnknowns.has(id)) fail("unknown_unknown", id);

const allowedActions = new Map(
  (context.allowed_actions ?? []).map((action) => [action.action_id, action]),
);
const actionIds = strings(result.advisory_action_ids, "advisory_action_ids", 1);
let previousOrdinal = 0;
for (const id of actionIds) {
  const action = allowedActions.get(id);
  if (action === undefined) {
    fail("unsupported_action", id);
    continue;
  }
  if (!Number.isSafeInteger(action.ordinal) || action.ordinal <= previousOrdinal) {
    fail("invalid_action_order", id);
  }
  previousOrdinal = action.ordinal;
}

const availableChecks = new Set(context.available_checks ?? []);
for (const check of strings(result.checks_performed, "checks_performed")) {
  if (!availableChecks.has(check)) fail("unavailable_check_claim", check);
}

const promotion = object(result.promotion, "promotion");
exactKeys(promotion, ["impact", "security_outcome", "headline_result"], "promotion");
if (promotion.impact !== "routine" && promotion.impact !== "high") {
  fail("invalid_schema", "promotion impact is invalid");
}
if (promotion.security_outcome !== true || promotion.headline_result !== false) {
  fail("invalid_promotion", "Security triage must require review and may not claim a headline");
}
if (!Array.isArray(result.external_mutations) || result.external_mutations.length !== 0) {
  fail("forbidden_external_mutation", "external_mutations must be empty");
}

const claimText = [summary, report, ...hypothesisText].join("\n");
if (
  /\b(?:confirmed|proven|definitive|conclusive)\s+(?:compromise|malware|breach|attribution|exfiltration|execution)\b/iu.test(
    claimText,
  )
) {
  fail("unsupported_definitive_claim", "Packet summaries cannot prove the claimed outcome");
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

const observationCoverage = ratio(observationSet, new Set(context.required_observation_ids ?? []));
const unknownCoverage = ratio(new Set(unknownIds), new Set(context.required_unknown_ids ?? []));
const actionCoverage = ratio(new Set(actionIds), new Set(allowedActions.keys()));
const score =
  Math.round((50 * observationCoverage + 30 * unknownCoverage + 20 * actionCoverage) * 1_000_000) /
  1_000_000;
const hardGateFailures = [
  ...new Map(failures.map((failure) => [`${failure.code}|${failure.detail}`, failure])).values(),
].sort(
  (left, right) => left.code.localeCompare(right.code) || left.detail.localeCompare(right.detail),
);
const evaluation = {
  schema_version: "1",
  evaluator_version: "pcap-security-evaluator-v1",
  passed: hardGateFailures.length === 0,
  hard_gate_failures: hardGateFailures,
  coverage: {
    important_observations: observationCoverage,
    explicit_unknowns: unknownCoverage,
    passive_actions: actionCoverage,
  },
  score,
};
process.stdout.write(`${JSON.stringify(evaluation)}\n`);
if (!evaluation.passed) process.exitCode = 1;
