import { execFile } from "node:child_process";
import { access, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import type { AgentRuntime, RuntimeTurnInput, RuntimeTurnResult } from "aiur-orchestrator";
import { RuntimeError } from "aiur-orchestrator";
import { Effect } from "effect";

const execFileAsync = promisify(execFile);

interface FakeEvaluationContext {
  readonly expected_severity: string;
  readonly boundary_ambiguous: boolean;
  readonly known_evidence_ids: ReadonlyArray<string>;
  readonly known_citations: ReadonlyArray<{
    readonly document_id: string;
    readonly section_id: string;
  }>;
  readonly known_metrics: ReadonlyArray<{
    readonly fact_id: string;
    readonly metric: string;
    readonly value: number;
  }>;
  readonly required_action_ids: ReadonlyArray<string>;
  readonly required_unknown_ids: ReadonlyArray<string>;
  readonly allowed_actions: ReadonlyArray<{
    readonly action_id: string;
    readonly ordinal: number;
    readonly rule_id: string;
    readonly prerequisites: ReadonlyArray<string>;
  }>;
  readonly available_checks: ReadonlyArray<string>;
}

const agentReport = JSON.stringify({
  status: "completed",
  summary: "Completed the assigned bounded phase.",
  evidence: ["Used only the immutable incident workspace."],
  risks: [],
  nextSteps: [],
});

function result(threadId: string, finalText: string): RuntimeTurnResult {
  return {
    threadId,
    finalText,
    usage: { inputTokens: 20, cachedInputTokens: 0, outputTokens: 20, totalTokens: 40 },
    events: [{ type: "templar.fake.turn" }],
  };
}

async function writeCandidate(input: RuntimeTurnInput, completeCoverage: boolean): Promise<void> {
  const context = JSON.parse(
    await readFile(path.join(input.cwd, "evaluation", "context.json"), "utf8"),
  ) as FakeEvaluationContext;
  const actions = context.allowed_actions
    .filter((action) => context.required_action_ids.includes(action.action_id))
    .filter((_action, index, all) => completeCoverage || index < all.length - 1)
    .map((action) => ({
      ordinal: action.ordinal,
      action_id: action.action_id,
      source_rule_ids: [action.rule_id],
      prerequisites: action.prerequisites,
    }));
  const evidenceIds = completeCoverage
    ? context.known_evidence_ids
    : context.known_evidence_ids.slice(0, Math.max(1, context.known_evidence_ids.length - 1));
  const unknownIds = completeCoverage
    ? context.required_unknown_ids
    : context.required_unknown_ids.slice(0, Math.max(0, context.required_unknown_ids.length - 1));
  const citations = context.known_citations.filter(
    (citation) =>
      citation.document_id === "SOP-NET-001" &&
      ["SOP-NET-001#1", "SOP-NET-001#2.1", "SOP-NET-001#2.2", "SOP-NET-001#3"].includes(
        citation.section_id,
      ),
  );
  const hasPolicyFinding = context.known_metrics.length > 0;
  const output = {
    schema_version: "1",
    status: context.boundary_ambiguous ? "needs_review" : "completed",
    summary: hasPolicyFinding
      ? `Packet evidence maps to ${context.expected_severity}; unresolved device checks remain.`
      : "The incident needs the declared local device checks; no packet metric was supplied.",
    severity: context.expected_severity,
    evidence_ids: evidenceIds,
    citations,
    metric_claims: context.known_metrics,
    findings: hasPolicyFinding
      ? [
          {
            finding_id: "finding.tcp_retransmission_policy",
            rule_id: "POLICY-TCP-RETRANS-001",
            severity: context.expected_severity,
            evidence_ids: ["evidence.pcap.capture"],
            statement: "The persisted retransmission metric was classified by the active policy.",
          },
        ]
      : [],
    action_plan: actions,
    unknown_ids: unknownIds,
    checks_performed: context.available_checks,
    evaluationAudit: {
      checks_rerun: ["deterministic_evaluator"],
      suspicious_behavior: [],
      findings: [],
      disposition: "pass",
      manualAuditRequired: false,
      trace_available: false,
    },
    promotion: {
      impact: context.expected_severity === "high" ? "high" : "routine",
      security_outcome: false,
      headline_result: false,
    },
    external_mutations: [],
  };
  await writeFile(
    path.join(input.cwd, "result.json"),
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    path.join(input.cwd, "report.md"),
    `# Network incident report\n\n${output.summary}\n\nEvidence and policy identifiers are recorded in result.json. No external mutation was performed.\n\n## Audit findings\n\nThe deterministic local evaluator was rerun; no suspicious candidate behavior was observed during the candidate self-check.\n`,
    "utf8",
  );
  for (let iteration = 0; iteration < 2; iteration += 1) {
    await execFileAsync("node", [path.join(input.cwd, "evaluation", "evaluate.mjs")], {
      cwd: input.cwd,
      encoding: "utf8",
      timeout: 10_000,
    }).catch(() => undefined);
  }
}

async function auditCandidate(input: RuntimeTurnInput): Promise<string> {
  const tracePath = path.join(input.cwd, ".harness-audit", "trace.jsonl");
  const traceAvailable = await access(tracePath).then(
    () => true,
    () => false,
  );
  let traceInspected = false;
  let traceComplete = false;
  if (traceAvailable) {
    try {
      const firstLine = (await readFile(tracePath, "utf8")).split("\n", 1)[0];
      const header = JSON.parse(firstLine ?? "null") as unknown;
      if (
        typeof header === "object" &&
        header !== null &&
        !Array.isArray(header) &&
        "type" in header &&
        header.type === "trace.header"
      ) {
        traceInspected = true;
        traceComplete = "truncated" in header && header.truncated === false;
      }
    } catch {
      traceInspected = false;
    }
  }
  const evaluation = await execFileAsync(
    "node",
    [path.join(input.cwd, "evaluation", "evaluate.mjs")],
    {
      cwd: input.cwd,
      encoding: "utf8",
      timeout: 10_000,
    },
  ).then(
    (run) => run.stdout.trim(),
    (error: unknown) =>
      typeof error === "object" && error !== null && "stdout" in error
        ? String(error.stdout).trim()
        : "evaluator failed",
  );
  let evaluatorPassed = false;
  try {
    const parsed = JSON.parse(evaluation) as unknown;
    evaluatorPassed =
      typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed) &&
      "passed" in parsed &&
      parsed.passed === true;
  } catch {
    evaluatorPassed = false;
  }
  const manualReview = !traceComplete || !evaluatorPassed;
  const traceFinding = !traceAvailable
    ? "candidate trace unavailable; degraded audit"
    : !traceInspected
      ? "candidate trace header malformed; degraded audit"
      : !traceComplete
        ? "candidate trace truncated; degraded audit"
        : "complete candidate trace inspected; no suspicious behavior found";
  return JSON.stringify({
    status: "completed",
    summary: manualReview
      ? "Reran the deterministic evaluator; trace or evaluator coverage requires manual review."
      : "Reran the deterministic evaluator and inspected the complete scoped trace; no gaming indicators were observed.",
    evidence: [
      "audit.checks_rerun=deterministic_evaluator,git_diff,evaluator_contract",
      "audit.suspicious_behavior=none",
      `audit.finding=${traceFinding}`,
      `audit.disposition=${manualReview ? "manual_review" : "pass"}`,
      `audit.manualAuditRequired=${manualReview ? "true" : "false"}`,
      `audit.trace_inspected=${traceInspected ? "true" : "false"}`,
      `audit.trace_complete=${traceComplete ? "true" : "false"}`,
      `audit.evaluator_output=${evaluation.slice(0, 1000)}`,
    ],
    risks: manualReview ? ["Evaluation-audit coverage is degraded and requires human review."] : [],
    nextSteps: manualReview ? ["Perform a complete manual trace audit before promotion."] : [],
  });
}

export class ScriptedTemplarRuntime implements AgentRuntime {
  #supervisorTurns = 0;

  readonly runTurn = (input: RuntimeTurnInput) =>
    Effect.tryPromise({
      try: async () => {
        if (input.agentId !== "supervisor") {
          if (input.agentId === "candidate_a") await writeCandidate(input, true);
          if (input.agentId === "candidate_b") await writeCandidate(input, false);
          const finalText = input.agentId.startsWith("audit_")
            ? await auditCandidate(input)
            : agentReport;
          return result(`${input.agentId}-thread`, finalText);
        }

        this.#supervisorTurns += 1;
        if (this.#supervisorTurns === 1) {
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "continue",
              summary: "Run the single read-only research phase.",
              assignments: [
                {
                  agentId: "research_once",
                  roleId: "evidence_researcher",
                  task: "Identify applicable evidence, rules, and missing facts.",
                  targetCandidateId: null,
                },
              ],
              selectedCandidateId: null,
            }),
          );
        }
        if (this.#supervisorTurns === 2) {
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "continue",
              summary: "Create two independent candidates.",
              assignments: [
                {
                  agentId: "candidate_a",
                  roleId: "diagnosis_candidate",
                  task: "Write the candidate outputs from immutable evidence.",
                  targetCandidateId: null,
                },
                {
                  agentId: "candidate_b",
                  roleId: "diagnosis_candidate",
                  task: "Write an independent candidate output.",
                  targetCandidateId: null,
                },
              ],
              selectedCandidateId: null,
            }),
          );
        }
        if (this.#supervisorTurns === 3) {
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "continue",
              summary: "Review both pinned candidate workspaces.",
              assignments: [
                {
                  agentId: "audit_a",
                  roleId: "evaluation_auditor",
                  task: "Audit candidate_a, rerun the evaluator, and inspect its scoped trace if present.",
                  targetCandidateId: "candidate_a",
                },
                {
                  agentId: "audit_b",
                  roleId: "evaluation_auditor",
                  task: "Audit candidate_b, rerun the evaluator, and inspect its scoped trace if present.",
                  targetCandidateId: "candidate_b",
                },
              ],
              selectedCandidateId: null,
            }),
          );
        }
        return result(
          "supervisor-thread",
          JSON.stringify({
            status: "accept",
            summary: "candidate_a has the highest deterministic passing coverage score.",
            assignments: [],
            selectedCandidateId: "candidate_a",
          }),
        );
      },
      catch: (cause) =>
        new RuntimeError({
          message: "Scripted Templar runtime failed",
          agentId: input.agentId,
          cause,
        }),
    });
}
