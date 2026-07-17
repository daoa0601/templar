import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { CORPUS_ID, DOCUMENT_SECTIONS, domainRoot, POLICY_ID } from "../src/corpus.js";
import { classifyRetransmissionRate, retransmissionPolicyFinding } from "../src/policy.js";

describe("versioned telecom policy and corpus", () => {
  it.each([
    [0, "none"],
    [0.999, "none"],
    [1, "low"],
    [2.999, "low"],
    [3, "boundary_ambiguous"],
    [3.001, "medium"],
    [6.999, "medium"],
    [7, "boundary_ambiguous"],
    [7.001, "high"],
  ] as const)("classifies %s as %s", (rate, severity) => {
    expect(classifyRetransmissionRate(rate)).toBe(severity);
  });

  it("preserves stable policy, document, section, and citation IDs", async () => {
    expect(CORPUS_ID).toBe("telecom-corpus-v1");
    expect(POLICY_ID).toBe("POLICY-TCP-RETRANS-001");
    expect(DOCUMENT_SECTIONS["SOP-NET-001"]).toEqual([
      "SOP-NET-001#1",
      "SOP-NET-001#2",
      "SOP-NET-001#2.1",
      "SOP-NET-001#2.2",
      "SOP-NET-001#3",
    ]);
    expect(retransmissionPolicyFinding(3).citations).toEqual([
      { document_id: "SOP-NET-001", section_id: "SOP-NET-001#1" },
    ]);
    expect(
      await readFile(path.join(domainRoot(), "documents", "sop_packet_loss.md"), "utf8"),
    ).toContain("**Document ID:** SOP-NET-001");
    expect(
      await readFile(path.join(domainRoot(), "documents", "cisco_catalyst_9300_config.md"), "utf8"),
    ).toContain("**Document ID:** HW-CFG-012");
  });
});
