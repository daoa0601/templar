import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

import { isExerciseSnapshotId } from "./contracts.js";
import { TemplarError } from "./errors.js";
import { decodeExerciseSnapshot } from "./exercise.js";
import type { ExerciseSnapshot } from "./exercise.js";

export interface StoredExerciseSnapshot {
  readonly artifact_id: string;
  readonly digest: string;
  readonly size: number;
  readonly media_type: "application/vnd.templar.exercise-snapshot+json";
}

function invalidArtifact(message: string, cause?: unknown): TemplarError {
  return new TemplarError({ code: "EXERCISE_INVALID", message, status: 400, cause });
}

function within(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative.length > 0 &&
    !relative.startsWith(`..${path.sep}`) &&
    relative !== ".." &&
    !path.isAbsolute(relative)
  );
}

export class ExerciseSnapshotStore {
  readonly root: string;
  readonly maxBytes: number;

  constructor(root: string, maxBytes: number) {
    this.root = path.resolve(root);
    this.maxBytes = maxBytes;
  }

  async initialize(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const info = await lstat(this.root);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw invalidArtifact("Configured exercise snapshot root must be a real directory.");
    }
  }

  async stage(value: unknown): Promise<StoredExerciseSnapshot> {
    const snapshot = decodeExerciseSnapshot(value);
    const bytes = Buffer.from(`${JSON.stringify(snapshot)}\n`, "utf8");
    if (bytes.byteLength > this.maxBytes) {
      throw new TemplarError({
        code: "EXERCISE_LIMIT_EXCEEDED",
        message: `Exercise snapshot exceeds the ${this.maxBytes}-byte limit.`,
        status: 413,
      });
    }
    await this.initialize();
    const digest = createHash("sha256").update(bytes).digest("hex");
    const artifactId = `exercise_sha256_${digest}`;
    const destination = path.join(this.root, `${digest}.json`);
    const temporary = path.join(this.root, `.${digest}.${randomUUID()}.tmp`);
    try {
      await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
      await rename(temporary, destination);
    } catch (cause) {
      await unlink(temporary).catch(() => undefined);
      throw invalidArtifact("Unable to stage exercise snapshot.", cause);
    }
    return {
      artifact_id: artifactId,
      digest: `sha256:${digest}`,
      size: bytes.byteLength,
      media_type: "application/vnd.templar.exercise-snapshot+json",
    };
  }

  async resolve(artifactId: string): Promise<ExerciseSnapshot> {
    if (!isExerciseSnapshotId(artifactId)) throw invalidArtifact("Invalid exercise snapshot ID.");
    await this.initialize();
    const digest = artifactId.slice("exercise_sha256_".length);
    const candidate = path.join(this.root, `${digest}.json`);
    if (!within(this.root, candidate)) throw invalidArtifact("Exercise snapshot escaped its root.");
    let info;
    try {
      info = await lstat(candidate);
    } catch (cause) {
      throw new TemplarError({
        code: "NOT_FOUND",
        message: "Exercise snapshot was not found.",
        status: 404,
        cause,
      });
    }
    if (!info.isFile() || info.isSymbolicLink()) {
      throw invalidArtifact("Exercise snapshot is not a regular file.");
    }
    if (info.size > this.maxBytes) {
      throw new TemplarError({
        code: "EXERCISE_LIMIT_EXCEEDED",
        message: "Stored exercise snapshot exceeds its configured byte cap.",
        status: 400,
      });
    }
    const rootReal = await realpath(this.root);
    const candidateReal = await realpath(candidate);
    if (!within(rootReal, candidateReal))
      throw invalidArtifact("Exercise snapshot escaped its root.");
    const bytes = await readFile(candidateReal);
    const observed = createHash("sha256").update(bytes).digest("hex");
    if (observed !== digest) throw invalidArtifact("Exercise snapshot digest verification failed.");
    try {
      return decodeExerciseSnapshot(JSON.parse(bytes.toString("utf8")) as unknown);
    } catch (cause) {
      throw invalidArtifact("Stored exercise snapshot is invalid.", cause);
    }
  }
}
