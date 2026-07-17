#!/usr/bin/env node
import { loadConfig } from "./config.js";
import { decodeIncidentInput } from "./contracts.js";
import { ScriptedTemplarRuntime } from "./fake-runtime.js";
import { startHttpServer } from "./http.js";
import { TemplarService } from "./service.js";

const SAMPLE = decodeIncidentInput({
  schema_version: "1",
  request:
    "Investigate reported packet loss and TCP retransmissions on the access network using only the supplied local evidence.",
  observations: [
    {
      observation_id: "user-impact",
      kind: "operator_note",
      value: "Users report intermittent latency.",
      unit: "text",
    },
  ],
  reported_priority: "medium",
});

async function wait(service: TemplarService, runId: string): Promise<void> {
  let previous = "";
  for (;;) {
    const run = await service.inspectRun(runId);
    const serialized = JSON.stringify(run);
    if (serialized !== previous) {
      process.stdout.write(`${serialized}\n`);
      previous = serialized;
    }
    if (!["queued", "running"].includes(run.status)) {
      if (run.status === "accepted" && run.applied === true) {
        process.stdout.write(`${JSON.stringify(await service.result(runId), null, 2)}\n`);
      }
      return;
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 500));
  }
}

async function main(): Promise<void> {
  const command = process.argv[2] ?? "serve";
  const config = loadConfig();
  if (command === "serve") {
    const service = new TemplarService(config);
    const server = await startHttpServer(service);
    const auth =
      config.bearerToken === undefined
        ? "loopback development mode without bearer auth"
        : "bearer authentication enabled";
    process.stdout.write(`Templar listening at ${server.origin} (${auth}).\n`);
    return;
  }
  if (command === "sample" || command === "demo") {
    const fake = command === "demo";
    const service = new TemplarService(
      config,
      fake ? { runtimeFactory: () => new ScriptedTemplarRuntime() } : {},
    );
    await service.initialize();
    const submitted = await service.submitTelecomIncident(SAMPLE);
    process.stdout.write(
      `${fake ? "Deterministic fake" : "Codex-backed"} run ${submitted.run_id} started.\n`,
    );
    await wait(service, submitted.run_id);
    return;
  }
  process.stderr.write("Usage: templar [serve|sample|demo]\n");
  process.exitCode = 2;
}

void main().catch((error: unknown) => {
  process.stderr.write(
    `Templar failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 1;
});
