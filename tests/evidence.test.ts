import { describe, expect, it } from "vitest";

import { decodeIncidentInput } from "../src/contracts.js";
import { buildEvidenceBundle } from "../src/evidence.js";
import { analyzeClassicPcapBytes } from "../src/pcap-analyzer.js";
import { classicPcap, tcpPacket } from "./helpers.js";

describe("Templar evidence model", () => {
  it("keeps immutable EvidenceItems, policy Findings, and interpretive Hypotheses separate", () => {
    const pcap = analyzeClassicPcapBytes(
      classicPcap([
        tcpPacket({ sequence: 10, flags: 0x18, payload: "x" }),
        tcpPacket({ sequence: 10, flags: 0x18, payload: "x" }),
      ]),
      `pcap_sha256_${"a".repeat(64)}`,
      { maxBytes: 1024 * 1024, maxPackets: 100 },
    );
    const built = buildEvidenceBundle(
      "evidence-test",
      decodeIncidentInput({ schema_version: "1", request: "Investigate packet retransmission" }),
      pcap,
    );

    const pcapEvidence = built.bundle.evidence_items.find(
      (item) => item.evidence_id === "evidence.pcap.capture",
    );
    expect(pcapEvidence).toMatchObject({
      source_kind: "pcap_artifact",
      sha256: `sha256:${"a".repeat(64)}`,
      parser_version: "classic-pcap-v1",
      provenance: { digest_verified: true },
    });
    expect(built.bundle.findings[0]).toMatchObject({
      finding_id: "finding.tcp_retransmission_policy",
      evidence_ids: ["evidence.pcap.capture"],
      fact_ids: ["fact.tcp.retransmissions"],
    });
    expect(built.bundle.hypotheses[0]).toMatchObject({
      hypothesis_id: "hypothesis.retransmission_contributes_to_reported_impact",
      finding_ids: ["finding.tcp_retransmission_policy"],
      confidence: "low",
    });
    expect(built.evaluation.known_evidence_ids).toEqual([
      "evidence.incident.request",
      "evidence.pcap.capture",
    ]);
    expect(built.evaluation.known_fact_ids).toContain("fact.tcp.retransmissions");
  });
});
