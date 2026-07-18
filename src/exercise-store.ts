import path from "node:path";

import {
  ContentAddressedFileStore,
  ContentAddressedStoreError,
} from "@agentic-orch/node-guardrails/cas";

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

export class ExerciseSnapshotStore {
  readonly root: string;
  readonly maxBytes: number;
  readonly #files: ContentAddressedFileStore;

  constructor(root: string, maxBytes: number) {
    this.root = path.resolve(root);
    this.maxBytes = maxBytes;
    this.#files = new ContentAddressedFileStore({
      root: this.root,
      maxBytes,
      extension: ".json",
    });
  }

  async initialize(): Promise<void> {
    try {
      await this.#files.initialize();
    } catch (cause) {
      throw invalidArtifact("Configured exercise snapshot root must be a real directory.", cause);
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
    let stored;
    try {
      stored = await this.#files.stage(bytes);
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError && cause.kind === "content_too_large") {
        throw new TemplarError({
          code: "EXERCISE_LIMIT_EXCEEDED",
          message: `Exercise snapshot exceeds the ${this.maxBytes}-byte limit.`,
          status: 413,
          cause,
        });
      }
      throw invalidArtifact("Unable to stage exercise snapshot.", cause);
    }
    return {
      artifact_id: `exercise_sha256_${stored.digest}`,
      digest: `sha256:${stored.digest}`,
      size: stored.size,
      media_type: "application/vnd.templar.exercise-snapshot+json",
    };
  }

  async resolve(artifactId: string): Promise<ExerciseSnapshot> {
    if (!isExerciseSnapshotId(artifactId)) throw invalidArtifact("Invalid exercise snapshot ID.");
    const digest = artifactId.slice("exercise_sha256_".length);
    let bytes: Buffer;
    try {
      bytes = (await this.#files.read(digest)).bytes;
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError) {
        if (cause.kind === "not_found") {
          throw new TemplarError({
            code: "NOT_FOUND",
            message: "Exercise snapshot was not found.",
            status: 404,
            cause,
          });
        }
        if (cause.kind === "content_too_large") {
          throw new TemplarError({
            code: "EXERCISE_LIMIT_EXCEEDED",
            message: "Stored exercise snapshot exceeds its configured byte cap.",
            status: 400,
            cause,
          });
        }
        if (cause.kind === "invalid_file") {
          throw invalidArtifact("Exercise snapshot is not a regular file.", cause);
        }
        if (cause.kind === "digest_mismatch") {
          throw invalidArtifact("Exercise snapshot digest verification failed.", cause);
        }
      }
      throw invalidArtifact("Unable to resolve exercise snapshot.", cause);
    }
    try {
      return decodeExerciseSnapshot(JSON.parse(bytes.toString("utf8")) as unknown);
    } catch (cause) {
      throw invalidArtifact("Stored exercise snapshot is invalid.", cause);
    }
  }
}
