import path from "node:path";

import {
  ContentAddressedFileStore,
  ContentAddressedStoreError,
  type VerifiedContent,
} from "@agentic-orch/node-guardrails/cas";

import { isPcapArtifactId } from "./contracts.js";
import { TemplarError } from "./errors.js";
import { inspectClassicPcapHeader } from "./pcap-format.js";

export interface StoredPcapArtifact {
  readonly artifact_id: string;
  readonly digest: string;
  readonly size: number;
  readonly media_type: "application/vnd.tcpdump.pcap";
}

function invalidArtifact(message: string, cause?: unknown): TemplarError {
  return new TemplarError({ code: "PCAP_INVALID", message, status: 400, cause });
}

export class PcapArtifactStore {
  readonly root: string;
  readonly maxBytes: number;
  readonly #files: ContentAddressedFileStore;

  constructor(root: string, maxBytes: number) {
    this.root = path.resolve(root);
    this.maxBytes = maxBytes;
    this.#files = new ContentAddressedFileStore({
      root: this.root,
      maxBytes,
      extension: ".pcap",
    });
  }

  async initialize(): Promise<void> {
    try {
      await this.#files.initialize();
    } catch (cause) {
      throw invalidArtifact("Configured PCAP artifact root must be a real directory.", cause);
    }
  }

  async stage(bytes: Uint8Array): Promise<StoredPcapArtifact> {
    if (bytes.byteLength > this.maxBytes) {
      throw new TemplarError({
        code: "PCAP_LIMIT_EXCEEDED",
        message: `PCAP exceeds the ${this.maxBytes}-byte upload limit.`,
        status: 413,
      });
    }
    inspectClassicPcapHeader(bytes);
    let stored;
    try {
      stored = await this.#files.stage(bytes);
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError && cause.kind === "content_too_large") {
        throw new TemplarError({
          code: "PCAP_LIMIT_EXCEEDED",
          message: `PCAP exceeds the ${this.maxBytes}-byte upload limit.`,
          status: 413,
          cause,
        });
      }
      throw invalidArtifact("Unable to stage PCAP artifact.", cause);
    }
    return {
      artifact_id: `pcap_sha256_${stored.digest}`,
      digest: `sha256:${stored.digest}`,
      size: stored.size,
      media_type: "application/vnd.tcpdump.pcap",
    };
  }

  async read(artifactId: string): Promise<Buffer> {
    return (await this.#verified(artifactId)).bytes;
  }

  async #verified(artifactId: string): Promise<VerifiedContent> {
    if (!isPcapArtifactId(artifactId)) throw invalidArtifact("Invalid PCAP artifact ID.");
    const digest = artifactId.slice("pcap_sha256_".length);
    let verified: VerifiedContent;
    try {
      verified = await this.#files.read(digest);
    } catch (cause) {
      if (cause instanceof ContentAddressedStoreError) {
        if (cause.kind === "not_found") {
          throw new TemplarError({
            code: "NOT_FOUND",
            message: "PCAP artifact was not found.",
            status: 404,
            cause,
          });
        }
        if (cause.kind === "content_too_large") {
          throw new TemplarError({
            code: "PCAP_LIMIT_EXCEEDED",
            message: "Stored PCAP exceeds its configured byte cap.",
            status: 400,
            cause,
          });
        }
        if (cause.kind === "invalid_file") {
          throw invalidArtifact("PCAP artifact is not a regular file.", cause);
        }
        if (cause.kind === "digest_mismatch") {
          throw invalidArtifact("PCAP artifact digest verification failed.", cause);
        }
      }
      throw invalidArtifact("Unable to resolve PCAP artifact.", cause);
    }
    inspectClassicPcapHeader(verified.bytes);
    return verified;
  }
}
