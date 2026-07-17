import type { AgentRuntime } from "aiur-orchestrator";
import { Effect } from "effect";
import { afterEach, describe, expect, it } from "vitest";

import { ScriptedTemplarRuntime } from "../src/fake-runtime.js";
import { startHttpServer } from "../src/http.js";
import type { TemplarHttpServer } from "../src/http.js";
import { TemplarService } from "../src/service.js";
import { classicPcap, testConfig } from "./helpers.js";

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
      evaluationAudit: { auditorCount: 1, harnessEvaluator: { passed: true } },
      promotion: { eligible: true },
    });
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
