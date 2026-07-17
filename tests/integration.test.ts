import { readFile } from "node:fs/promises";
import path from "node:path";

import { readRunEventRecords } from "aiur-orchestrator";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { decodeIncidentInput, decodePcapSecurityTriageInput } from "../src/contracts.js";
import { ScriptedTemplarRuntime } from "../src/fake-runtime.js";
import { TemplarService } from "../src/service.js";
import { classicPcap, tcpPacket, testConfig } from "./helpers.js";

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
