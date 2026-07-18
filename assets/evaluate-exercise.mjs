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

function string(value, label, maximum = 8000) {
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
  const values = value.map((entry, index) => string(entry, `${label}[${index}]`, 256));
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

if (report.trim().length === 0 || report.length > 64_000) {
  fail("invalid_schema", "report.md must be bounded and non-empty");
}
for (const heading of ["Answers", "Method", "Uncertainty"]) {
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
    "answers",
    "unanswered_question_ids",
    "evidence_checks_relied_on",
    "checks_performed",
    "external_mutations",
  ],
  "result",
);
if (result.schema_version !== "1") fail("invalid_schema", "schema_version must be 1");
if (result.status !== "completed" && result.status !== "incomplete") {
  fail("invalid_schema", "status is invalid");
}
string(result.summary, "summary", 2000);

const knownQuestions = new Set(context.known_question_ids ?? []);
const requiredQuestions = new Set(context.required_question_ids ?? []);
const knownObservations = new Set(context.known_observation_ids ?? []);
const requiredObservations = new Set(context.required_observation_ids ?? []);
const questionObservationNamespaces = new Map(
  (Array.isArray(context.question_observation_namespaces)
    ? context.question_observation_namespaces
    : []
  ).map((entry) => [entry.question_id, entry.observation_prefix]),
);
const answered = new Set();
const cited = new Set();

if (!Array.isArray(result.answers) || result.answers.length === 0) {
  fail("invalid_schema", "answers must contain at least one entry");
}
for (const [index, raw] of (Array.isArray(result.answers) ? result.answers : []).entries()) {
  const answer = object(raw, `answers[${index}]`);
  exactKeys(
    answer,
    ["question_id", "answer", "observation_ids", "uncertainty"],
    `answers[${index}]`,
  );
  const questionId = string(answer.question_id, `answers[${index}].question_id`, 128);
  if (!knownQuestions.has(questionId)) fail("unknown_question", questionId);
  if (answered.has(questionId)) fail("duplicate_answer", questionId);
  answered.add(questionId);
  string(answer.answer, `answers[${index}].answer`);
  string(answer.uncertainty, `answers[${index}].uncertainty`, 1000);
  for (const observationId of strings(
    answer.observation_ids,
    `answers[${index}].observation_ids`,
    1,
  )) {
    if (!knownObservations.has(observationId)) fail("unknown_observation", observationId);
    const namespace = questionObservationNamespaces.get(questionId);
    if (typeof namespace === "string" && !observationId.startsWith(namespace)) {
      fail("cross_assignment_observation", `${questionId}:${observationId}`);
    }
    cited.add(observationId);
  }
}

const unanswered = new Set(strings(result.unanswered_question_ids, "unanswered_question_ids"));
for (const questionId of unanswered) {
  if (!knownQuestions.has(questionId)) fail("unknown_question", questionId);
  if (answered.has(questionId)) fail("question_answered_and_unanswered", questionId);
}
for (const questionId of requiredQuestions) {
  if (!answered.has(questionId)) fail("missing_answer", questionId);
}
if (unanswered.size > 0 || result.status !== "completed") {
  fail("incomplete_result", "A passing exercise attempt must answer every required question");
}

const availableEvidenceChecks = new Set(context.available_evidence_checks ?? []);
const reliedOnEvidenceChecks = new Set(
  strings(result.evidence_checks_relied_on, "evidence_checks_relied_on", 1),
);
for (const check of reliedOnEvidenceChecks) {
  if (!availableEvidenceChecks.has(check)) fail("unavailable_evidence_check_claim", check);
}
const availableCandidateChecks = new Set(context.candidate_checks_available ?? []);
const performedChecks = new Set(strings(result.checks_performed, "checks_performed", 1));
for (const check of performedChecks) {
  if (!availableCandidateChecks.has(check)) fail("unavailable_candidate_check_claim", check);
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

const questionCoverage = ratio(answered, requiredQuestions);
const observationCoverage = ratio(cited, requiredObservations);
const evidenceCheckCoverage = ratio(reliedOnEvidenceChecks, availableEvidenceChecks);
const candidateCheckCoverage = ratio(performedChecks, availableCandidateChecks);
const score =
  Math.round(
    (60 * questionCoverage +
      30 * observationCoverage +
      5 * evidenceCheckCoverage +
      5 * candidateCheckCoverage) *
      1_000_000,
  ) / 1_000_000;
const hardGateFailures = [
  ...new Map(failures.map((failure) => [`${failure.code}|${failure.detail}`, failure])).values(),
].sort(
  (left, right) => left.code.localeCompare(right.code) || left.detail.localeCompare(right.detail),
);
const evaluation = {
  schema_version: "1",
  evaluator_version: "exercise-evaluator-v2",
  passed: hardGateFailures.length === 0,
  hard_gate_failures: hardGateFailures,
  coverage: {
    questions: questionCoverage,
    observations: observationCoverage,
    evidence_checks: evidenceCheckCoverage,
    candidate_checks: candidateCheckCoverage,
  },
  score,
};
process.stdout.write(`${JSON.stringify(evaluation)}\n`);
if (!evaluation.passed) process.exitCode = 1;
