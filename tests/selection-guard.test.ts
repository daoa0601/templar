import { describe, expect, it } from "vitest";

import { deterministicSelectionFromSupervisorPrompt } from "../src/selection-guard.js";

function prompt(scores: readonly [number, number], includeBothAuditors = true): string {
  const observations = [
    {
      roleId: "evaluation_auditor",
      targetCandidateId: "candidate_a",
      report: { status: "completed", evidence: ["audit.disposition=pass"] },
    },
    ...(includeBothAuditors
      ? [
          {
            roleId: "evaluation_auditor",
            targetCandidateId: "candidate_b",
            report: { status: "completed", evidence: ["audit.disposition=pass"] },
          },
        ]
      : []),
  ];
  const candidates = ["candidate_a", "candidate_b"].map((candidateId, index) => ({
    candidateId,
    evaluation: {
      passed: true,
      stdoutTail: JSON.stringify({ passed: true, score: scores[index] }),
    },
  }));
  return `Fresh observations from the previous worker batch:
${JSON.stringify(observations, null, 2)}

Current candidate snapshots. Full patches are durable artifacts; reviewers can inspect a chosen
candidate directly when assigned with targetCandidateId:
${JSON.stringify(candidates, null, 2)}

Harness rules you cannot override:
- bounded`;
}

describe("mechanical candidate selection", () => {
  it("selects the highest independent evaluator score", () => {
    expect(deterministicSelectionFromSupervisorPrompt(prompt([72, 91]))).toMatchObject({
      ready: true,
      selectedCandidateId: "candidate_b",
      reason: "highest_deterministic_score_then_candidate_ordinal",
    });
  });

  it("breaks an exact score tie by candidate ordinal", () => {
    expect(deterministicSelectionFromSupervisorPrompt(prompt([88, 88])).selectedCandidateId).toBe(
      "candidate_a",
    );
  });

  it("refuses acceptance until both candidate-pinned auditors have completed", () => {
    expect(deterministicSelectionFromSupervisorPrompt(prompt([100, 50], false))).toMatchObject({
      ready: false,
      reason: "pinned_evaluation_auditor_missing:candidate_b",
    });
  });
});
