#!/usr/bin/env node
import { constants } from "node:fs";
import { open, writeFile } from "node:fs/promises";
import path from "node:path";

import { makeOpenCodeRuntime } from "@agentic-orch/agent-blocks/templates/scoped-worktree/adapters/opencode-cli";

import { loadConfig } from "./config.js";
import { decodeExerciseSolveInput, decodeIncidentInput } from "./contracts.js";
import { buildCourseExerciseSnapshot } from "./course-evidence.js";
import { gradeCourseCandidate } from "./course-grade.js";
import { CourseLabController } from "./course-lab.js";
import { inventoryCourseCorpus, loadCourseCorpusManifest } from "./course-corpus.js";
import { DroneClient } from "./drone-client.js";
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

async function boundedJson(
  filePathInput: string,
  maximumBytes = 16 * 1024 * 1024,
): Promise<unknown> {
  const filePath = path.resolve(filePathInput);
  const handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size <= 0 || before.size > maximumBytes) {
      throw new Error(`JSON input must be a 1-${maximumBytes} byte regular file.`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (
      after.size !== before.size ||
      after.ino !== before.ino ||
      after.dev !== before.dev ||
      bytes.length !== before.size
    ) {
      throw new Error("JSON input changed while it was being read.");
    }
    return JSON.parse(bytes.toString("utf8")) as unknown;
  } finally {
    await handle.close();
  }
}

async function emitJson(value: unknown, destination?: string): Promise<void> {
  const serialized = `${JSON.stringify(value, null, 2)}\n`;
  if (destination === undefined) {
    process.stdout.write(serialized);
    return;
  }
  await writeFile(path.resolve(destination), serialized, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
}

type CourseRuntime = "codex" | "opencode";

function courseRunOptions(args: ReadonlyArray<string>): {
  readonly runtime: CourseRuntime;
  readonly model: string | undefined;
} {
  if (args.length % 2 !== 0) {
    throw new Error(
      "Usage: templar course [solve|demo] <snapshot.json> [--runtime codex|opencode] [--model <model>] or templar course lab solve <lab-id> [--runtime codex|opencode] [--model <model>]",
    );
  }
  const options = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (
      key === undefined ||
      value === undefined ||
      !["--runtime", "--model"].includes(key) ||
      options.has(key)
    ) {
      throw new Error(
        "Usage: templar course [solve|demo] <snapshot.json> [--runtime codex|opencode] [--model <model>] or templar course lab solve <lab-id> [--runtime codex|opencode] [--model <model>]",
      );
    }
    options.set(key, value);
  }
  const runtime = options.get("--runtime") ?? process.env.TEMPLAR_COURSE_RUNTIME ?? "codex";
  if (runtime !== "codex" && runtime !== "opencode") {
    throw new Error("The course runtime must be codex or opencode.");
  }
  const configuredModel = options.get("--model") ?? process.env.TEMPLAR_COURSE_MODEL;
  return {
    runtime,
    model: configuredModel ?? (runtime === "opencode" ? "zai-coding-plan/glm-5.2" : undefined),
  };
}

function courseLabSubmitOptions(args: ReadonlyArray<string>): {
  readonly approvedProviderAttestationId: string;
  readonly rationale: string;
} {
  if (args.length !== 4) {
    throw new Error(
      "Usage: templar course lab submit <source-artifact-id> <specimen-file> <media-type> --approve-attestation <attestation-id> --rationale <text>",
    );
  }
  const options = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (
      key === undefined ||
      value === undefined ||
      !["--approve-attestation", "--rationale"].includes(key) ||
      options.has(key)
    ) {
      throw new Error(
        "Usage: templar course lab submit <source-artifact-id> <specimen-file> <media-type> --approve-attestation <attestation-id> --rationale <text>",
      );
    }
    options.set(key, value);
  }
  const approvedProviderAttestationId = options.get("--approve-attestation");
  const rationale = options.get("--rationale");
  if (approvedProviderAttestationId === undefined || rationale === undefined) {
    throw new Error("Course-lab submission requires attestation approval and a rationale.");
  }
  return { approvedProviderAttestationId, rationale };
}

async function main(): Promise<void> {
  const command = process.argv[2] ?? "serve";
  if (command === "course" && process.argv[3] === "inventory") {
    const courseRoot = process.argv[4] ?? process.env.TEMPLAR_COURSE_MATERIAL;
    if (courseRoot === undefined) {
      throw new Error("Usage: templar course inventory <course-material-root>");
    }
    const inventory = await inventoryCourseCorpus(courseRoot);
    process.stdout.write(`${JSON.stringify(inventory, null, 2)}\n`);
    if (!inventory.complete) process.exitCode = 1;
    return;
  }
  if (command === "course" && process.argv[3] === "compose") {
    const courseRoot = process.argv[4] ?? process.env.TEMPLAR_COURSE_MATERIAL;
    const evidencePath = process.argv[5];
    if (courseRoot === undefined || evidencePath === undefined) {
      throw new Error(
        "Usage: templar course compose <course-material-root> <assignment-evidence.json> [snapshot.json]",
      );
    }
    const manifest = await loadCourseCorpusManifest();
    const inventory = await inventoryCourseCorpus(courseRoot, manifest);
    const snapshot = buildCourseExerciseSnapshot({
      manifest,
      inventory,
      assignments: await boundedJson(evidencePath),
    });
    await emitJson(snapshot, process.argv[6]);
    return;
  }
  if (command === "course" && process.argv[3] === "grade") {
    const candidatePath = process.argv[4];
    const rubricPath = process.argv[5];
    if (candidatePath === undefined || rubricPath === undefined) {
      throw new Error("Usage: templar course grade <result.json> <sealed-rubric.json>");
    }
    const grade = gradeCourseCandidate({
      candidate: await boundedJson(candidatePath),
      rubric: await boundedJson(rubricPath),
      manifest: await loadCourseCorpusManifest(),
    });
    await emitJson(grade);
    if (!grade.passed) process.exitCode = 1;
    return;
  }
  const config = loadConfig();
  const courseLab = (): CourseLabController =>
    new CourseLabController(
      config,
      new DroneClient({
        baseUrl: config.droneUrl,
        ...(config.droneToken === undefined ? {} : { token: config.droneToken }),
        timeoutMs: config.droneTimeoutMs,
        maxArtifactResponseBytes: config.maxExerciseSnapshotBytes,
      }),
    );
  if (command === "course" && process.argv[3] === "lab" && process.argv[4] === "submit") {
    const sourceArtifactId = process.argv[5];
    const specimenFile = process.argv[6];
    const specimenMediaType = process.argv[7];
    if (
      sourceArtifactId === undefined ||
      specimenFile === undefined ||
      specimenMediaType === undefined
    ) {
      throw new Error(
        "Usage: templar course lab submit <source-artifact-id> <specimen-file> <media-type> --approve-attestation <attestation-id> --rationale <text>",
      );
    }
    const approval = courseLabSubmitOptions(process.argv.slice(8));
    await emitJson(
      await courseLab().submit({
        sourceArtifactId,
        specimenFile,
        specimenMediaType,
        ...approval,
      }),
    );
    return;
  }
  if (command === "course" && process.argv[3] === "lab" && process.argv[4] === "status") {
    const id = process.argv[5];
    if (id === undefined || process.argv.length !== 6) {
      throw new Error("Usage: templar course lab status <lab-id>");
    }
    await emitJson(await courseLab().status(id));
    return;
  }
  if (command === "course" && process.argv[3] === "lab" && process.argv[4] === "collect") {
    const id = process.argv[5];
    const destination = process.argv[6];
    if (id === undefined || destination === undefined || process.argv.length !== 7) {
      throw new Error("Usage: templar course lab collect <lab-id> <assignment-evidence.json>");
    }
    await emitJson(await courseLab().collect(id, destination));
    return;
  }
  if (command === "course" && process.argv[3] === "lab" && process.argv[4] === "snapshot") {
    const id = process.argv[5];
    const destination = process.argv[6];
    if (id === undefined || destination === undefined || process.argv.length !== 7) {
      throw new Error("Usage: templar course lab snapshot <lab-id> <exercise-snapshot.json>");
    }
    await emitJson(await courseLab().exerciseSnapshot(id), destination);
    return;
  }
  if (command === "course" && process.argv[3] === "lab" && process.argv[4] === "solve") {
    const id = process.argv[5];
    if (id === undefined) {
      throw new Error(
        "Usage: templar course lab solve <lab-id> [--runtime codex|opencode] [--model <model>]",
      );
    }
    const options = courseRunOptions(process.argv.slice(6));
    const openCodeRuntime =
      options.runtime === "opencode"
        ? makeOpenCodeRuntime({
            binary: process.env.TEMPLAR_OPENCODE_BINARY?.trim() || "opencode",
            maxOutputBytes: 6 * 1024 * 1024,
          })
        : undefined;
    const service = new TemplarService(config, {
      ...(openCodeRuntime === undefined ? {} : { runtimeFactory: () => openCodeRuntime }),
      ...(options.model === undefined ? {} : { courseAssignmentModel: options.model }),
    });
    await service.initialize();
    const artifact = await service.stageExerciseSnapshot(await courseLab().exerciseSnapshot(id));
    const submitted = await service.submitExerciseSolve(
      decodeExerciseSolveInput({
        schema_version: "1",
        exercise_snapshot_id: artifact.artifact_id,
      }),
    );
    process.stdout.write(
      `${options.runtime === "opencode" ? "OpenCode-backed" : "Codex-backed"} attested course-assignment run ${submitted.run_id} started.\n`,
    );
    await wait(service, submitted.run_id);
    return;
  }
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
  if (command === "course" && (process.argv[3] === "solve" || process.argv[3] === "demo")) {
    const snapshotPath = process.argv[4];
    if (snapshotPath === undefined) {
      throw new Error(
        "Usage: templar course [solve|demo] <snapshot.json> [--runtime codex|opencode] [--model <model>]",
      );
    }
    const options = courseRunOptions(process.argv.slice(5));
    const fake = process.argv[3] === "demo";
    const openCodeRuntime =
      !fake && options.runtime === "opencode"
        ? makeOpenCodeRuntime({
            binary: process.env.TEMPLAR_OPENCODE_BINARY?.trim() || "opencode",
            maxOutputBytes: 12 * 1024 * 1024,
          })
        : undefined;
    const service = new TemplarService(config, {
      ...(fake
        ? { runtimeFactory: () => new ScriptedTemplarRuntime() }
        : openCodeRuntime === undefined
          ? {}
          : { runtimeFactory: () => openCodeRuntime }),
      ...(options.model === undefined ? {} : { courseModel: options.model }),
    });
    await service.initialize();
    const artifact = await service.stageExerciseSnapshot(await boundedJson(snapshotPath));
    const submitted = await service.submitExerciseSolve(
      decodeExerciseSolveInput({
        schema_version: "1",
        exercise_snapshot_id: artifact.artifact_id,
      }),
    );
    process.stdout.write(
      `${fake ? "Deterministic fake" : options.runtime === "opencode" ? "OpenCode-backed" : "Codex-backed"} course run ${submitted.run_id} started.\n`,
    );
    await wait(service, submitted.run_id);
    return;
  }
  process.stderr.write(
    "Usage: templar [serve|sample|demo|course inventory <root>|course compose <root> <evidence.json> [snapshot.json]|course lab submit <source-artifact-id> <specimen-file> <media-type> --approve-attestation <attestation-id> --rationale <text>|course lab status <lab-id>|course lab collect <lab-id> <assignment-evidence.json>|course lab snapshot <lab-id> <exercise-snapshot.json>|course lab solve <lab-id> [--runtime codex|opencode] [--model <model>]|course solve <snapshot.json> [--runtime codex|opencode] [--model <model>]|course demo <snapshot.json> [--runtime codex|opencode] [--model <model>]|course grade <result.json> <sealed-rubric.json>]\n",
  );
  process.exitCode = 2;
}

void main().catch((error: unknown) => {
  process.stderr.write(
    `Templar failed: ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 1;
});
