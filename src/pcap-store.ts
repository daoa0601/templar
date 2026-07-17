import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdir, readFile, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

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

function within(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative.length > 0 &&
    !relative.startsWith(`..${path.sep}`) &&
    relative !== ".." &&
    !path.isAbsolute(relative)
  );
}

export class PcapArtifactStore {
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
      throw invalidArtifact("Configured PCAP artifact root must be a real directory.");
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
    await this.initialize();
    const digest = createHash("sha256").update(bytes).digest("hex");
    const artifactId = `pcap_sha256_${digest}`;
    const destination = path.join(this.root, `${digest}.pcap`);
    const temporary = path.join(this.root, `.${digest}.${randomUUID()}.tmp`);
    try {
      await writeFile(temporary, bytes, { flag: "wx", mode: 0o600 });
      await rename(temporary, destination);
    } catch (cause) {
      await unlink(temporary).catch(() => undefined);
      throw invalidArtifact("Unable to stage PCAP artifact.", cause);
    }
    return {
      artifact_id: artifactId,
      digest: `sha256:${digest}`,
      size: bytes.byteLength,
      media_type: "application/vnd.tcpdump.pcap",
    };
  }

  async resolve(artifactId: string): Promise<string> {
    if (!isPcapArtifactId(artifactId)) throw invalidArtifact("Invalid PCAP artifact ID.");
    await this.initialize();
    const digest = artifactId.slice("pcap_sha256_".length);
    const candidate = path.join(this.root, `${digest}.pcap`);
    if (!within(this.root, candidate)) throw invalidArtifact("PCAP artifact escaped its root.");
    let info;
    try {
      info = await lstat(candidate);
    } catch (cause) {
      throw new TemplarError({
        code: "NOT_FOUND",
        message: "PCAP artifact was not found.",
        status: 404,
        cause,
      });
    }
    if (!info.isFile() || info.isSymbolicLink())
      throw invalidArtifact("PCAP artifact is not a regular file.");
    if (info.size > this.maxBytes) {
      throw new TemplarError({
        code: "PCAP_LIMIT_EXCEEDED",
        message: "Stored PCAP exceeds its configured byte cap.",
        status: 400,
      });
    }
    const rootReal = await realpath(this.root);
    const candidateReal = await realpath(candidate);
    if (!within(rootReal, candidateReal)) throw invalidArtifact("PCAP artifact escaped its root.");
    const bytes = await readFile(candidateReal);
    const observed = createHash("sha256").update(bytes).digest("hex");
    if (observed !== digest) throw invalidArtifact("PCAP artifact digest verification failed.");
    inspectClassicPcapHeader(bytes);
    return candidateReal;
  }
}
