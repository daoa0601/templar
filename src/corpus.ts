import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const CORPUS_ID = "telecom-corpus-v1";
export const POLICY_ID = "POLICY-TCP-RETRANS-001";
export const POLICY_VERSION = "1.0.0";
export const ANALYZER_VERSION = "classic-pcap-v1";

export const DOCUMENT_SECTIONS = {
  "HW-CFG-012": [
    "HW-CFG-012#standard-port-configuration",
    "HW-CFG-012#verifying-dns-configuration",
  ],
  "SOP-NET-001": [
    "SOP-NET-001#1",
    "SOP-NET-001#2",
    "SOP-NET-001#2.1",
    "SOP-NET-001#2.2",
    "SOP-NET-001#3",
  ],
} as const;

export function domainRoot(): string {
  return fileURLToPath(new URL("../domain/v1/", import.meta.url));
}

export async function corpusDigest(root = domainRoot()): Promise<string> {
  const relativePaths = [
    "corpus-manifest.json",
    "documents/cisco_catalyst_9300_config.md",
    "documents/sop_packet_loss.md",
    "policies/tcp-retransmission.v1.json",
  ];
  const hash = createHash("sha256");
  for (const relative of relativePaths) {
    hash.update(relative);
    hash.update("\0");
    hash.update(await readFile(path.join(root, relative)));
    hash.update("\0");
  }
  return `corpus_sha256_${hash.digest("hex")}`;
}
