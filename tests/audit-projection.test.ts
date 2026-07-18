import type { RunEventRecord } from "@agentic-orch/agent-blocks/persistence";
import { describe, expect, it } from "vitest";

import { projectEvaluationAudit } from "../src/service.js";

const SELF_AUDIT = {
  evaluationAudit: {
    checks_rerun: ["deterministic_evaluator"],
    suspicious_behavior: [],
    findings: [],
    disposition: "pass",
    manualAuditRequired: false,
    trace_available: false,
  },
};

function record(sequence: number, type: string, fields: Record<string, unknown>): RunEventRecord {
  return {
    schemaVersion: 1,
    runId: "audit-projection",
    sequence,
    at: `2026-07-17T00:00:0${sequence}.000Z`,
    type,
    ...fields,
  };
}

function auditRecords(
  options: {
    readonly disposition?: "pass" | "manual_review";
    readonly auditorTraceComplete?: boolean;
    readonly omitTraceMarker?: boolean;
    readonly truncated?: boolean;
  } = {},
): ReadonlyArray<RunEventRecord> {
  const disposition = options.disposition ?? "pass";
  const evidence = [
    "audit.checks_rerun=deterministic_evaluator,git_diff,evaluator_contract",
    "audit.suspicious_behavior=none",
    "audit.finding=no suspicious behavior found",
    `audit.disposition=${disposition}`,
    `audit.manualAuditRequired=${disposition === "manual_review" ? "true" : "false"}`,
    ...(!options.omitTraceMarker
      ? [
          "audit.trace_inspected=true",
          `audit.trace_complete=${options.auditorTraceComplete === false ? "false" : "true"}`,
        ]
      : []),
  ];
  return [
    record(1, "harness.private.audit_materialized", {
      candidateId: "candidate_a",
      truncated: options.truncated ?? false,
      omittedRecords: options.truncated === true ? 2 : 0,
    }),
    record(2, "candidate.snapshot", {
      candidateId: "candidate_a",
      evaluation: { passed: true, exitCode: 0, durationMs: 5 },
    }),
    record(3, "agent.turn_completed", {
      roleId: "evaluation_auditor",
      targetCandidateId: "candidate_a",
      report: { status: "completed", evidence, risks: [], nextSteps: [] },
    }),
  ];
}

describe("structured evaluation audit projection", () => {
  it("extracts stable markers from trusted private records without returning raw reports", () => {
    expect(projectEvaluationAudit(auditRecords(), "candidate_a", SELF_AUDIT)).toEqual({
      checksRerun: ["deterministic_evaluator", "evaluator_contract", "git_diff"],
      suspiciousBehavior: [],
      findings: ["no suspicious behavior found"],
      disposition: "pass",
      manualAuditRequired: false,
      candidateSelfAudit: SELF_AUDIT.evaluationAudit,
      auditorCount: 1,
      traceInspected: true,
      traceComplete: true,
      harnessEvaluator: { passed: true, exitCode: 0, durationMs: 5 },
    });
  });

  it("honors audit.disposition=manual_review as a promotion gate", () => {
    expect(
      projectEvaluationAudit(
        auditRecords({ disposition: "manual_review" }),
        "candidate_a",
        SELF_AUDIT,
      ),
    ).toMatchObject({ disposition: "manual_review", manualAuditRequired: true });
  });

  it("degrades absent markers and truncated trusted traces to manual review", () => {
    const missing = projectEvaluationAudit(
      auditRecords({ omitTraceMarker: true }),
      "candidate_a",
      SELF_AUDIT,
    );
    expect(missing.manualAuditRequired).toBe(true);
    expect(missing.traceComplete).toBe(false);
    expect(missing.findings.join(" ")).toMatch(/omitted one or more required/u);

    const truncated = projectEvaluationAudit(
      auditRecords({ truncated: true }),
      "candidate_a",
      SELF_AUDIT,
    );
    expect(truncated).toMatchObject({ traceComplete: false, manualAuditRequired: true });
    expect(truncated.findings.join(" ")).toMatch(/trace was truncated/u);
  });

  it("does not report a complete audit when the independent auditor says its trace review was incomplete", () => {
    expect(
      projectEvaluationAudit(
        auditRecords({ auditorTraceComplete: false }),
        "candidate_a",
        SELF_AUDIT,
      ),
    ).toMatchObject({
      traceComplete: false,
      manualAuditRequired: true,
      disposition: "manual_review",
    });
  });

  it("projects evaluator-only workflows without inventing a missing-auditor failure", () => {
    expect(
      projectEvaluationAudit(
        auditRecords().slice(1, 2),
        "candidate_a",
        {},
        {
          traceAuditorRequired: false,
        },
      ),
    ).toEqual({
      checksRerun: ["deterministic_evaluator"],
      suspiciousBehavior: [],
      findings: [],
      disposition: "pass",
      manualAuditRequired: false,
      candidateSelfAudit: undefined,
      auditorCount: 0,
      traceInspected: false,
      traceComplete: false,
      harnessEvaluator: { passed: true, exitCode: 0, durationMs: 5 },
    });
  });
});
