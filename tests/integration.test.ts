import { readFile } from "node:fs/promises";
import path from "node:path";

import { readRunEventRecords } from "@agentic-orch/agent-blocks/persistence";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import {
  decodeExerciseSolveInput,
  decodeIncidentInput,
  decodePcapSecurityTriageInput,
} from "../src/contracts.js";
import {
  buildCourseExerciseSnapshot,
  courseChecksForAnalysisMode,
} from "../src/course-evidence.js";
import { loadCourseCorpusManifest } from "../src/course-corpus.js";
import { ScriptedTemplarRuntime } from "../src/fake-runtime.js";
import { TemplarService } from "../src/service.js";
import { classicPcap, tcpPacket, testConfig } from "./helpers.js";
import { exerciseSnapshot } from "./exercise-fixture.js";

async function waitForTerminal(service: TemplarService, runId: string) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const run = await service.inspectRun(runId);
    if (run.status !== "queued" && run.status !== "running") return run;
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("fake Templar run did not finish");
}

describe("real harness integration with a scripted non-billing runtime", () => {
  it("runs research, two isolated candidates, pinned auditors, evaluators, selection, apply, and durable queries", async () => {
    const config = await testConfig();
    const runtime = new ScriptedTemplarRuntime();
    const service = new TemplarService(config, { runtimeFactory: () => runtime });
    await service.initialize();
    const submitted = await service.submitTelecomIncident(
      decodeIncidentInput({
        schema_version: "1",
        request: "Investigate packet loss using the supplied bounded evidence.",
      }),
    );
    expect(["queued", "running"]).toContain(submitted.run.status);

    const run = await waitForTerminal(service, submitted.run_id);
    expect(run).toMatchObject({
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
      rounds: 4,
      agentTurns: 5,
      totalAgents: 5,
    });
    expect((await service.listRuns())[0]?.runId).toBe(submitted.run_id);

    const records = await Effect.runPromise(
      readRunEventRecords(config.harnessHome, submitted.run_id),
    );
    const worktrees = records
      .filter((event) => event.type === "candidate.worktree_created")
      .map((event) => event.worktreePath);
    expect(worktrees).toHaveLength(2);
    expect(new Set(worktrees).size).toBe(2);
    expect(records.filter((event) => event.type === "candidate.snapshot")).toHaveLength(2);
    expect(records.filter((event) => event.roleId === "evidence_researcher")).toHaveLength(2);
    expect(
      records.filter(
        (event) => event.roleId === "evaluation_auditor" && event.type === "agent.turn_completed",
      ),
    ).toHaveLength(2);

    const scores = records
      .filter((event) => event.type === "candidate.snapshot")
      .map((event) => {
        const evaluation = event.evaluation as { readonly stdout?: string } | undefined;
        return evaluation?.stdout === undefined
          ? undefined
          : (JSON.parse(evaluation.stdout) as { readonly score: number }).score;
      });
    expect(scores).toEqual([100, 83.333333]);

    const output = await service.result(submitted.run_id);
    expect(output.evaluation).toMatchObject({
      strategy: "deterministic_evaluator_with_review",
      passed: true,
      manualReviewRequired: false,
      evaluator: { passed: true },
      review: { auditorCount: 1, traceInspected: true, traceComplete: true },
    });
    expect(output.promotion).toMatchObject({ eligible: true, acknowledged: false });
    expect(
      await readFile(path.join(service.incidentDirectory(submitted.run_id), "result.json"), "utf8"),
    ).toContain("evidence.incident.request");
  }, 20_000);

  it("runs lean PCAP security research, two isolated analysts, evaluation, and selection", async () => {
    const config = await testConfig();
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    await service.initialize();
    const artifact = await service.stagePcap(
      classicPcap([
        tcpPacket({
          sequence: 1,
          flags: 0x02,
          destinationPort: 25,
          destination: [10, 0, 0, 2],
        }),
        tcpPacket({
          sequence: 2,
          flags: 0x02,
          destinationPort: 3389,
          destination: [10, 0, 0, 3],
        }),
      ]),
    );
    const submitted = await service.submitPcapSecurityTriage(
      decodePcapSecurityTriageInput({
        schema_version: "1",
        pcap_artifact_id: artifact.artifact_id,
      }),
    );

    expect(await waitForTerminal(service, submitted.run_id)).toMatchObject({
      workflow: "pcap_security_triage",
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
      rounds: 3,
      agentTurns: 3,
      totalAgents: 3,
    });
    const records = await Effect.runPromise(
      readRunEventRecords(config.harnessHome, submitted.run_id),
    );
    expect(
      records.filter(
        (event) =>
          event.roleId === "security_evidence_researcher" && event.type === "agent.turn_completed",
      ),
    ).toHaveLength(1);
    expect(
      records.filter(
        (event) => event.roleId === "evaluation_auditor" && event.type === "agent.turn_completed",
      ),
    ).toHaveLength(0);
    const scores = records
      .filter((event) => event.type === "candidate.snapshot")
      .map((event) => {
        const evaluation = event.evaluation as { readonly stdout?: string } | undefined;
        return evaluation?.stdout === undefined
          ? undefined
          : (JSON.parse(evaluation.stdout) as { readonly score: number }).score;
      });
    expect(scores).toEqual([100, 83.75]);

    const output = await service.result(submitted.run_id);
    expect(output.result).toMatchObject({
      assessment: "suspicious_needs_review",
      promotion: { security_outcome: true, headline_result: false },
      external_mutations: [],
    });
    expect(output.evaluation).toMatchObject({
      strategy: "deterministic_evaluator",
      passed: true,
      manualReviewRequired: false,
      evaluator: { passed: true },
      review: null,
    });
    expect(output.promotion).toMatchObject({
      requiresHumanAcknowledgment: true,
      reasons: ["security_result"],
      acknowledged: false,
      eligible: false,
    });
  }, 20_000);

  it("runs a bounded static exercise through research, two solvers, and deterministic selection", async () => {
    const config = await testConfig();
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    await service.initialize();
    const artifact = await service.stageExerciseSnapshot(exerciseSnapshot());
    const submitted = await service.submitExerciseSolve(
      decodeExerciseSolveInput({
        schema_version: "1",
        exercise_snapshot_id: artifact.artifact_id,
      }),
    );

    expect(await waitForTerminal(service, submitted.run_id)).toMatchObject({
      workflow: "exercise_solve",
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
      rounds: 3,
      agentTurns: 3,
      totalAgents: 3,
    });
    const records = await Effect.runPromise(
      readRunEventRecords(config.harnessHome, submitted.run_id),
    );
    expect(
      records.filter(
        (event) => event.roleId === "exercise_researcher" && event.type === "agent.turn_completed",
      ),
    ).toHaveLength(1);
    expect(
      records.filter(
        (event) => event.roleId === "evaluation_auditor" && event.type === "agent.turn_completed",
      ),
    ).toHaveLength(0);
    const scores = records
      .filter((event) => event.type === "candidate.snapshot")
      .map((event) => {
        const evaluation = event.evaluation as { readonly stdout?: string } | undefined;
        return evaluation?.stdout === undefined
          ? undefined
          : (JSON.parse(evaluation.stdout) as { readonly score: number }).score;
      });
    expect(scores).toEqual([100, 85]);

    const output = await service.result(submitted.run_id);
    expect(output.result).toMatchObject({
      status: "completed",
      unanswered_question_ids: [],
      external_mutations: [],
    });
    expect(output.evaluation).toMatchObject({
      strategy: "deterministic_evaluator",
      passed: true,
      review: null,
    });
    expect(output.promotion).toMatchObject({
      requiresHumanAcknowledgment: false,
      eligible: true,
    });
  }, 20_000);

  it("enforces the full purple, red/RE, blue, and assurance course organization", async () => {
    const manifest = await loadCourseCorpusManifest();
    const snapshot = buildCourseExerciseSnapshot({
      manifest,
      inventory: {
        schema_version: "1",
        corpus_id: manifest.corpus_id,
        course_root: "/fixture-course-root",
        assignment_count: manifest.assignments.length,
        requirement_count: manifest.requirement_count,
        verified_artifact_count: manifest.artifacts.length,
        complete: true,
        artifacts: manifest.artifacts.map((artifact) => ({
          artifact_id: artifact.artifact_id,
          assignment_id: artifact.assignment_id,
          path: `/fixture-course-root/${artifact.relative_path}`,
          status: "verified" as const,
          expected_byte_length: artifact.byte_length,
          actual_byte_length: artifact.byte_length,
          expected_sha256: artifact.sha256,
          actual_sha256: artifact.sha256,
        })),
      },
      assignments: manifest.assignments.map((assignment) => ({
        assignment_id: assignment.assignment_id,
        questions: assignment.requirement_ids.map((questionId) => ({
          question_id: questionId,
          prompt: `Bounded fixture prompt for ${questionId}.`,
        })),
        observations: [
          {
            observation_id: `${assignment.assignment_id}.observation.fixture`,
            kind: "bounded_passive_evidence",
            text:
              assignment.assignment_id === "darkwood-batch"
                ? Array.from(
                    { length: 60 },
                    (_, index) => `${String(index).padStart(2, "0")},${"a".repeat(70)}`,
                  ).join("\n")
                : `Passive fixture facts for ${assignment.assignment_id}.`,
            artifact_ids: assignment.artifact_ids,
            required: true,
          },
        ],
        check_ids: courseChecksForAnalysisMode(assignment.analysis_mode),
      })),
    });
    const config = await testConfig({ maxExerciseSnapshotBytes: 1024 * 1024 });
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    await service.initialize();
    const artifact = await service.stageExerciseSnapshot(snapshot);
    const submitted = await service.submitExerciseSolve(
      decodeExerciseSolveInput({
        schema_version: "1",
        exercise_snapshot_id: artifact.artifact_id,
      }),
    );

    expect(await waitForTerminal(service, submitted.run_id)).toMatchObject({
      workflow: "course_security_evaluation",
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
      rounds: 5,
      agentTurns: 9,
      totalAgents: 9,
    });
    const records = await Effect.runPromise(
      readRunEventRecords(config.harnessHome, submitted.run_id),
    );
    expect(records.find((event) => event.type === "run.started")).toMatchObject({
      runtime: {
        adapter: "templar-scripted",
        binary: null,
        ignoreUserConfig: true,
        toolPolicy: "scripted-no-model",
      },
    });
    const scores = records
      .filter((event) => event.type === "candidate.snapshot")
      .map((event) => {
        const evaluation = event.evaluation as { readonly stdout?: unknown };
        return typeof evaluation.stdout === "string"
          ? (JSON.parse(evaluation.stdout) as { readonly score: number }).score
          : undefined;
      });
    expect(scores).toEqual([100, 100]);
    for (const roleId of [
      "course_evidence_coordinator",
      "course_windows_intrusion_specialist",
      "course_native_re_specialist",
      "course_managed_re_specialist",
      "course_batch_re_specialist",
      "course_whole_corpus_solver",
      "evaluation_auditor",
    ]) {
      expect(
        records.some((event) => event.type === "agent.turn_completed" && event.roleId === roleId),
      ).toBe(true);
    }
    const output = await service.result(submitted.run_id);
    expect(output.result).toMatchObject({
      status: "completed",
      unanswered_question_ids: [],
      external_mutations: [],
    });
    expect((output.result as { answers: unknown[] }).answers).toHaveLength(33);
    expect(output.evaluation).toMatchObject({
      strategy: "deterministic_evaluator_with_review",
      passed: true,
      manualReviewRequired: false,
      review: { auditorCount: 1, traceInspected: true, traceComplete: true },
    });
  }, 30_000);

  it("completes a PCAP-backed fake run and persists an immutable high-impact acknowledgment", async () => {
    const config = await testConfig();
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    await service.initialize();
    const artifact = await service.stagePcap(
      classicPcap([
        tcpPacket({ sequence: 10, flags: 0x18, payload: "payload" }),
        tcpPacket({ sequence: 10, flags: 0x18, payload: "payload" }),
      ]),
    );
    const submitted = await service.submitTelecomIncident(
      decodeIncidentInput({
        schema_version: "1",
        request: "Investigate packet loss and retransmission evidence.",
        pcap_artifact_id: artifact.artifact_id,
      }),
    );
    expect(await waitForTerminal(service, submitted.run_id)).toMatchObject({
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
    });

    const before = await service.result(submitted.run_id);
    expect(before.result).toMatchObject({
      severity: "high",
      evidence_ids: ["evidence.incident.request", "evidence.pcap.capture"],
      findings: [{ evidence_ids: ["evidence.pcap.capture"] }],
      promotion: { impact: "high" },
    });
    expect(before.promotion).toMatchObject({
      requiresHumanAcknowledgment: true,
      acknowledged: false,
      eligible: false,
      reasons: ["high_impact_result"],
    });

    const rationale = "Reviewed packet evidence and bounded advisory actions.";
    const acknowledged = await service.acknowledgePromotion(submitted.run_id, rationale);
    expect(acknowledged.promotion).toMatchObject({ acknowledged: true, eligible: true });
    const acknowledgmentPath = path.join(
      config.templarHome,
      "acknowledgements",
      `${submitted.run_id}.json`,
    );
    const first = await readFile(acknowledgmentPath, "utf8");
    await expect(service.acknowledgePromotion(submitted.run_id, rationale)).resolves.toMatchObject({
      promotion: { acknowledged: true },
    });
    await expect(
      service.acknowledgePromotion(
        submitted.run_id,
        "A different operator rationale must not replace the record.",
      ),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(await readFile(acknowledgmentPath, "utf8")).toBe(first);
  }, 20_000);
});
