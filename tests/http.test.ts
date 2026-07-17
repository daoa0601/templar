import type { AgentRuntime } from "aiur-orchestrator";
import { Effect } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { ScriptedTemplarRuntime } from "../src/fake-runtime.js";
import { startHttpServer } from "../src/http.js";
import type { TemplarHttpServer } from "../src/http.js";
import { TemplarService } from "../src/service.js";
import { exerciseSnapshot } from "./exercise-fixture.js";
import { classicPcap, tcpPacket, testConfig } from "./helpers.js";

const TOKEN = "local-test-token";
const AUTH = { Authorization: `Bearer ${TOKEN}` };
const servers: Array<TemplarHttpServer> = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => server.close()));
});

async function terminal(origin: string, runId: string): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const response = await fetch(`${origin}/api/runs/${runId}`, { headers: AUTH });
    const run = (await response.json()) as Record<string, unknown>;
    if (run.status !== "queued" && run.status !== "running") return run;
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("HTTP fake run did not finish");
}

describe("Templar HTTP and dashboard boundaries", () => {
  it("enforces API auth/body caps while serving health and static Templar assets", async () => {
    const config = await testConfig({ bearerToken: TOKEN, maxJsonBytes: 256 });
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    const server = await startHttpServer(service, { port: 0 });
    servers.push(server);

    expect(await (await fetch(`${server.origin}/health/live`)).json()).toEqual({ status: "ok" });
    expect((await fetch(`${server.origin}/api/runs`)).status).toBe(401);
    expect((await fetch(`${server.origin}/api/runs`, { headers: AUTH })).status).toBe(200);

    const page = await (await fetch(`${server.origin}/`)).text();
    const script = await (await fetch(`${server.origin}/app.js`)).text();
    expect(page).toContain("<title>Templar</title>");
    expect(page).toContain("exercise_solve");
    expect(script).toContain('api("/api/runs")');
    expect(script).not.toMatch(/codex|openai|jira|dispatchAgent|selectCandidate/iu);

    const oversized = await fetch(`${server.origin}/api/incidents`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/json" },
      body: JSON.stringify({ schema_version: "1", request: "x".repeat(300) }),
    });
    expect(oversized.status).toBe(413);
    expect(await oversized.json()).toMatchObject({ error: { code: "BODY_TOO_LARGE" } });

    const staged = await fetch(`${server.origin}/api/artifacts/pcap`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/vnd.tcpdump.pcap" },
      body: classicPcap([]),
    });
    expect(staged.status).toBe(201);
    expect(await staged.json()).toMatchObject({
      artifact_id: expect.stringMatching(/^pcap_sha256_[a-f0-9]{64}$/u),
    });

    expect(await (await fetch(`${server.origin}/api/labs`, { headers: AUTH })).json()).toEqual([
      expect.objectContaining({
        provider_id: "parallels_desktop",
        enabled: false,
        mutations_available: false,
      }),
    ]);
  });

  it("exposes durable run/event/result routes without leaking private agent reports", async () => {
    const config = await testConfig({ bearerToken: TOKEN });
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    const server = await startHttpServer(service, { port: 0 });
    servers.push(server);
    const submittedResponse = await fetch(`${server.origin}/api/incidents`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/json" },
      body: JSON.stringify({
        schema_version: "1",
        request: "Investigate bounded packet loss evidence.",
      }),
    });
    expect(submittedResponse.status).toBe(202);
    const submitted = (await submittedResponse.json()) as { readonly run_id: string };
    expect(await terminal(server.origin, submitted.run_id)).toMatchObject({
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
    });

    const eventsResponse = await fetch(
      `${server.origin}/api/runs/${submitted.run_id}/events?after=0`,
      { headers: AUTH },
    );
    const events = (await eventsResponse.json()) as ReadonlyArray<Record<string, unknown>>;
    expect(events.some((event) => event.type === "candidate.snapshot")).toBe(true);
    const serialized = JSON.stringify(events);
    expect(serialized).not.toMatch(/"report"|"prompt"|"threadId"|trace\.jsonl/iu);

    const result = (await (
      await fetch(`${server.origin}/api/runs/${submitted.run_id}/result`, { headers: AUTH })
    ).json()) as Record<string, unknown>;
    expect(result).toMatchObject({
      evaluation: {
        strategy: "deterministic_evaluator_with_review",
        evaluator: { passed: true },
        review: { auditorCount: 1 },
      },
      promotion: { eligible: true },
    });
  }, 20_000);

  it("routes strict PCAP security input through the scoped security workflow", async () => {
    const config = await testConfig({ bearerToken: TOKEN });
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    const server = await startHttpServer(service, { port: 0 });
    servers.push(server);

    const page = await (await fetch(`${server.origin}/`)).text();
    expect(page).toContain("pcap_security_triage");
    const artifactResponse = await fetch(`${server.origin}/api/artifacts/pcap`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/vnd.tcpdump.pcap" },
      body: classicPcap([tcpPacket({ sequence: 1, flags: 0x02, destinationPort: 3389 })]),
    });
    const artifact = (await artifactResponse.json()) as { readonly artifact_id: string };
    const submittedResponse = await fetch(
      `${server.origin}/api/workflows/pcap_security_triage/runs`,
      {
        method: "POST",
        headers: { ...AUTH, "Content-Type": "application/json" },
        body: JSON.stringify({
          schema_version: "1",
          pcap_artifact_id: artifact.artifact_id,
        }),
      },
    );
    expect(submittedResponse.status).toBe(202);
    const submitted = (await submittedResponse.json()) as { readonly run_id: string };
    expect(await terminal(server.origin, submitted.run_id)).toMatchObject({
      workflow: "pcap_security_triage",
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
    });
    expect(
      await (
        await fetch(`${server.origin}/api/runs/${submitted.run_id}/result`, { headers: AUTH })
      ).json(),
    ).toMatchObject({
      result: { assessment: "suspicious_needs_review" },
      evaluation: {
        strategy: "deterministic_evaluator",
        passed: true,
        manualReviewRequired: false,
        review: null,
      },
      promotion: { reasons: ["security_result"], eligible: false },
    });

    const wrongShape = await fetch(`${server.origin}/api/workflows/pcap_security_triage/runs`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/json" },
      body: JSON.stringify({
        schema_version: "1",
        pcap_artifact_id: artifact.artifact_id,
        request: "This field is not part of the security workflow.",
      }),
    });
    expect(wrongShape.status).toBe(400);
  }, 20_000);

  it("stages and solves a strict bounded exercise snapshot", async () => {
    const config = await testConfig({ bearerToken: TOKEN });
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    const server = await startHttpServer(service, { port: 0 });
    servers.push(server);

    const stagedResponse = await fetch(`${server.origin}/api/artifacts/exercise-snapshot`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/json" },
      body: JSON.stringify(exerciseSnapshot()),
    });
    expect(stagedResponse.status).toBe(201);
    const artifact = (await stagedResponse.json()) as { readonly artifact_id: string };
    expect(artifact.artifact_id).toMatch(/^exercise_sha256_[a-f0-9]{64}$/u);

    const submittedResponse = await fetch(`${server.origin}/api/workflows/exercise_solve/runs`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/json" },
      body: JSON.stringify({
        schema_version: "1",
        exercise_snapshot_id: artifact.artifact_id,
      }),
    });
    expect(submittedResponse.status).toBe(202);
    const submitted = (await submittedResponse.json()) as { readonly run_id: string };
    expect(await terminal(server.origin, submitted.run_id)).toMatchObject({
      workflow: "exercise_solve",
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
    });
    expect(
      await (
        await fetch(`${server.origin}/api/runs/${submitted.run_id}/result`, { headers: AUTH })
      ).json(),
    ).toMatchObject({
      result: { status: "completed", unanswered_question_ids: [] },
      evaluation: { strategy: "deterministic_evaluator", passed: true, review: null },
      promotion: { requiresHumanAcknowledgment: false, eligible: true },
    });

    const wrongShape = await fetch(`${server.origin}/api/workflows/exercise_solve/runs`, {
      method: "POST",
      headers: { ...AUTH, "Content-Type": "application/json" },
      body: JSON.stringify({
        schema_version: "1",
        exercise_snapshot_id: artifact.artifact_id,
        command: "objdump",
      }),
    });
    expect(wrongShape.status).toBe(400);
  }, 20_000);

  it("interrupts only a live process-owned fiber and exposes the durable terminal state", async () => {
    const config = await testConfig({ bearerToken: TOKEN });
    const hangingRuntime: AgentRuntime = { runTurn: () => Effect.never };
    const service = new TemplarService(config, { runtimeFactory: () => hangingRuntime });
    const server = await startHttpServer(service, { port: 0 });
    servers.push(server);
    const submitted = (await (
      await fetch(`${server.origin}/api/incidents`, {
        method: "POST",
        headers: { ...AUTH, "Content-Type": "application/json" },
        body: JSON.stringify({ schema_version: "1", request: "Wait for cancellation." }),
      })
    ).json()) as { readonly run_id: string };

    const cancellation = await fetch(`${server.origin}/api/runs/${submitted.run_id}/cancel`, {
      method: "POST",
      headers: AUTH,
    });
    expect(cancellation.status).toBe(200);
    expect(await cancellation.json()).toMatchObject({ status: "interrupted" });
    expect(service.activeRunCount).toBe(0);
  }, 10_000);
});
