import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, symlink, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { ExerciseSnapshotStore } from "../src/exercise-store.js";
import { decodeExerciseSnapshot } from "../src/exercise.js";
import { initializeExerciseSolveWorkspace } from "../src/workspace.js";
import { exerciseSnapshot } from "./exercise-fixture.js";
import { temporaryDirectory } from "./helpers.js";

const execFileAsync = promisify(execFile);

async function writeCandidate(root: string, mutate?: (value: Record<string, unknown>) => void) {
  const output: Record<string, unknown> = {
    schema_version: "1",
    status: "completed",
    summary: "Answered both questions from the bounded static evidence.",
    answers: [
      {
        question_id: "question.1",
        answer: "The sample creates a GUI window.",
        observation_ids: ["observation.pe.headers"],
        uncertainty: "Runtime behavior was not observed.",
      },
      {
        question_id: "question.2",
        answer: "The compared value begins at 0x31.",
        observation_ids: ["observation.target.disassembly"],
        uncertainty: "The bounded excerpt does not show later transformations.",
      },
    ],
    unanswered_question_ids: [],
    evidence_checks_relied_on: ["pe_headers", "targeted_disassembly"],
    checks_performed: ["deterministic_evaluator"],
    external_mutations: [],
  };
  mutate?.(output);
  await writeFile(path.join(root, "result.json"), `${JSON.stringify(output, null, 2)}\n`, "utf8");
  await writeFile(
    path.join(root, "report.md"),
    "# Answers\n\nAnswers are structured in result.json.\n\n# Method\n\nRead bounded headers and disassembly.\n\n# Uncertainty\n\nNo execution was performed.\n",
    "utf8",
  );
}

async function evaluate(root: string): Promise<Record<string, unknown>> {
  try {
    const run = await execFileAsync("node", [path.join(root, "evaluation", "evaluate.mjs")], {
      cwd: root,
      encoding: "utf8",
    });
    return JSON.parse(run.stdout) as Record<string, unknown>;
  } catch (error) {
    const stdout =
      typeof error === "object" && error !== null && "stdout" in error
        ? String(error.stdout)
        : "{}";
    return JSON.parse(stdout) as Record<string, unknown>;
  }
}

describe("bounded exercise snapshots", () => {
  it("strictly decodes, content-addresses, and resolves a snapshot", async () => {
    expect(() =>
      decodeExerciseSnapshot({ ...exerciseSnapshot(), path: "/tmp/sample.exe" }),
    ).toThrow(/strict schema/iu);
    const root = await temporaryDirectory("templar-exercise-store-");
    const store = new ExerciseSnapshotStore(root, 256 * 1024);
    const staged = await store.stage(exerciseSnapshot());
    expect(staged.artifact_id).toMatch(/^exercise_sha256_[a-f0-9]{64}$/u);
    await expect(store.resolve(staged.artifact_id)).resolves.toEqual(exerciseSnapshot());
  });

  it("rejects symlinks, oversized custody files, and digest-valid invalid JSON", async () => {
    const root = await temporaryDirectory("templar-exercise-custody-");
    const store = new ExerciseSnapshotStore(root, 256 * 1024);
    const staged = await store.stage(exerciseSnapshot());
    const stagedPath = path.join(
      root,
      `${staged.artifact_id.slice("exercise_sha256_".length)}.json`,
    );
    await unlink(stagedPath);
    await symlink("/dev/null", stagedPath);
    await expect(store.resolve(staged.artifact_id)).rejects.toMatchObject({
      code: "EXERCISE_INVALID",
      status: 400,
    });

    const invalid = Buffer.from("not-json\n");
    const invalidDigest = createHash("sha256").update(invalid).digest("hex");
    await writeFile(path.join(root, `${invalidDigest}.json`), invalid, { mode: 0o600 });
    await expect(store.resolve(`exercise_sha256_${invalidDigest}`)).rejects.toMatchObject({
      code: "EXERCISE_INVALID",
      status: 400,
    });

    const oversized = Buffer.alloc(256 * 1024 + 1, 0x20);
    const oversizedDigest = createHash("sha256").update(oversized).digest("hex");
    await writeFile(path.join(root, `${oversizedDigest}.json`), oversized, { mode: 0o600 });
    await expect(store.resolve(`exercise_sha256_${oversizedDigest}`)).rejects.toMatchObject({
      code: "EXERCISE_LIMIT_EXCEEDED",
      status: 400,
    });
  });

  it("creates a binary-free workspace and evaluates a fully grounded answer", async () => {
    const templarHome = await temporaryDirectory("templar-exercise-workspace-");
    const workspace = await initializeExerciseSolveWorkspace({
      templarHome,
      runId: "exercise-workspace-test",
      snapshot: exerciseSnapshot(),
    });
    const tracked = await execFileAsync("git", ["ls-files"], {
      cwd: workspace.root,
      encoding: "utf8",
    });
    expect(tracked.stdout).toContain("exercise.json");
    expect(tracked.stdout).toContain("observations/index.json");
    expect(tracked.stdout).not.toMatch(/\.exe|\.bin|course-material/iu);
    expect(
      await readFile(path.join(workspace.root, "CANDIDATE_INSTRUCTIONS.md"), "utf8"),
    ).not.toContain("/Users/");
    const observationIndex = JSON.parse(
      await readFile(path.join(workspace.root, "observations", "index.json"), "utf8"),
    ) as {
      observations: ReadonlyArray<{ readonly file: string; readonly encoding: string }>;
    };
    expect(observationIndex.observations[0]!.encoding).toBe("raw-utf8-v1");
    expect(
      await readFile(
        path.join(workspace.root, "observations", observationIndex.observations[0]!.file),
        "utf8",
      ),
    ).toBe(exerciseSnapshot().observations[0]!.text);

    await writeCandidate(workspace.root);
    expect(await evaluate(workspace.root)).toMatchObject({
      passed: true,
      score: 100,
      evaluator_version: "exercise-evaluator-v2",
      coverage: { evidence_checks: 1, candidate_checks: 1 },
    });
  });

  it("materializes long observation strings as reconstructable line-bounded evidence", async () => {
    const templarHome = await temporaryDirectory("templar-exercise-chunks-");
    const snapshot = exerciseSnapshot();
    const longText = `${"A".repeat(2_500)}\n${"β".repeat(2_500)}`;
    const workspace = await initializeExerciseSolveWorkspace({
      templarHome,
      runId: "exercise-chunks-test",
      snapshot: {
        ...snapshot,
        observations: [
          { ...snapshot.observations[0]!, text: longText },
          ...snapshot.observations.slice(1),
        ],
      },
    });
    const index = JSON.parse(
      await readFile(path.join(workspace.root, "observations", "index.json"), "utf8"),
    ) as {
      observations: ReadonlyArray<{ readonly file: string; readonly digest: string }>;
    };
    const mirror = await readFile(
      path.join(workspace.root, "observations", index.observations[0]!.file),
      "utf8",
    );
    expect(
      Math.max(
        ...mirror
          .trimEnd()
          .split("\n")
          .map((line) => line.length),
      ),
    ).toBeLessThan(2_000);
    const reconstructed = mirror
      .trimEnd()
      .split("\n")
      .map((line) => (JSON.parse(line) as { text: string }).text)
      .join("");
    expect(reconstructed).toBe(longText);
    expect(index.observations[0]!.digest).toBe(
      `sha256:${createHash("sha256").update(longText, "utf8").digest("hex")}`,
    );
  });

  it("rejects unknown evidence and incomplete answers", async () => {
    const templarHome = await temporaryDirectory("templar-exercise-invalid-");
    const workspace = await initializeExerciseSolveWorkspace({
      templarHome,
      runId: "exercise-invalid-test",
      snapshot: exerciseSnapshot(),
    });
    await writeCandidate(workspace.root, (value) => {
      value.answers = [
        {
          question_id: "question.1",
          answer: "Unsupported answer.",
          observation_ids: ["observation.fabricated"],
          uncertainty: "none",
        },
      ];
      value.status = "incomplete";
      value.unanswered_question_ids = ["question.2"];
    });
    const evaluation = await evaluate(workspace.root);
    expect(evaluation.passed).toBe(false);
    expect(JSON.stringify(evaluation.hard_gate_failures)).toMatch(
      /unknown_observation|missing_answer|incomplete_result/iu,
    );
  });
});
