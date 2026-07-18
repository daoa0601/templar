import path from "node:path";

import {
  ContentAddressedFileStore,
  ContentAddressedStoreError,
} from "@agentic-orch/node-guardrails/cas";

import { isSourceSnapshotId } from "./contracts.js";
import { TemplarError } from "./errors.js";
import { decodeSourceSnapshot } from "./source.js";
import type { SourceSnapshot } from "./source.js";

export interface StoredSourceSnapshot {
  readonly artifact_id: string;
  readonly digest: string;
  readonly size: number;
  readonly media_type: "application/vnd.templar.source-snapshot+json";
}

function invalidArtifact(message: string, cause?: unknown): TemplarError {
  return new TemplarError({ code: "SOURCE_INVALID", message, status: 400, cause });
}

function sourceLimit(message: string, status: 400 | 413, cause?: unknown): TemplarError {
  return new TemplarError({ code: "SOURCE_LIMIT_EXCEEDED", message, status, cause });
}

export class SourceSnapshotStore {
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
      throw invalidArtifact("Configured source snapshot root must be a real directory.", cause);
    }
  }

  async stage(value: unknown): Promise<StoredSourceSnapshot> {
    const snapshot = decodeSourceSnapshot(value);
    const bytes = Buffer.from(`${JSON.stringify(snapshot)}\n`, "utf8");
    if (bytes.byteLength > this.maxBytes) {
      throw sourceLimit(`Source snapshot exceeds the ${this.maxBytes}-byte limit.`, 413);
    }

    let stored;
    try {
      stored = await this.#files.stage(bytes);
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError && cause.kind === "content_too_large") {
        throw sourceLimit(`Source snapshot exceeds the ${this.maxBytes}-byte limit.`, 413, cause);
      }
      // Root, destination-integrity, and I/O failures are deliberately not presented as
      // caller-addressable IDs or missing artifacts. The public message contains no pathname.
      throw invalidArtifact("Unable to stage source snapshot.", cause);
    }
    return {
      artifact_id: `source_sha256_${stored.digest}`,
      digest: `sha256:${stored.digest}`,
      size: stored.size,
      media_type: "application/vnd.templar.source-snapshot+json",
    };
  }

  async resolve(artifactId: string): Promise<SourceSnapshot> {
    if (!isSourceSnapshotId(artifactId)) throw invalidArtifact("Invalid source snapshot ID.");
    const digest = artifactId.slice("source_sha256_".length);

    let bytes: Buffer;
    try {
      // Decode only the bytes verified through the CAS file handle. No verified pathname is
      // returned to this domain layer and subsequently reopened.
      bytes = (await this.#files.read(digest)).bytes;
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError) {
        switch (cause.kind) {
          case "not_found":
            throw new TemplarError({
              code: "NOT_FOUND",
              message: "Source snapshot was not found.",
              status: 404,
              cause,
            });
          case "content_too_large":
            throw sourceLimit(
              "Stored source snapshot exceeds its configured byte cap.",
              400,
              cause,
            );
          case "digest_mismatch":
            throw invalidArtifact("Source snapshot digest verification failed.", cause);
          case "invalid_file":
            throw invalidArtifact("Source snapshot is not a regular file.", cause);
          case "empty_content":
            throw invalidArtifact("Stored source snapshot is invalid.", cause);
          case "invalid_digest":
            // The public ID validator makes this unreachable unless the two contracts diverge.
            throw invalidArtifact("Invalid source snapshot ID.", cause);
          case "invalid_root":
          case "io_error":
            throw invalidArtifact("Unable to resolve source snapshot.", cause);
        }
      }
      throw invalidArtifact("Unable to resolve source snapshot.", cause);
    }
    try {
      return decodeSourceSnapshot(JSON.parse(bytes.toString("utf8")) as unknown);
    } catch (cause) {
      throw invalidArtifact("Stored source snapshot is invalid.", cause);
    }
  }
}
