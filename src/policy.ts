export type RetransmissionSeverity = "none" | "low" | "medium" | "high" | "boundary_ambiguous";

export interface PolicyFinding {
  readonly finding_id: "finding.tcp_retransmission_policy";
  readonly rule_id: "POLICY-TCP-RETRANS-001";
  readonly severity: RetransmissionSeverity;
  readonly evidence_ids: ReadonlyArray<string>;
  readonly fact_ids: ReadonlyArray<string>;
  readonly statement: string;
  readonly citations: ReadonlyArray<{
    readonly document_id: "SOP-NET-001";
    readonly section_id: "SOP-NET-001#1";
  }>;
  readonly requires_human_review: boolean;
}

export function classifyRetransmissionRate(rate: number): RetransmissionSeverity {
  if (!Number.isFinite(rate) || rate < 0) throw new Error("rate must be a finite percentage >= 0");
  if (Object.is(rate, 3) || Object.is(rate, 7)) return "boundary_ambiguous";
  if (rate < 1) return "none";
  if (rate < 3) return "low";
  if (rate < 7) return "medium";
  return "high";
}

export function retransmissionPolicyFinding(
  rate: number,
  evidenceId = "evidence.pcap.capture",
  factId = "fact.tcp.retransmissions",
): PolicyFinding {
  const severity = classifyRetransmissionRate(rate);
  const ambiguous = severity === "boundary_ambiguous";
  return {
    finding_id: "finding.tcp_retransmission_policy",
    rule_id: "POLICY-TCP-RETRANS-001",
    severity,
    evidence_ids: [evidenceId],
    fact_ids: [factId],
    statement: ambiguous
      ? `${rate}% is an overlapping SOP-NET-001 boundary and requires human review.`
      : `${rate}% maps to ${severity} under POLICY-TCP-RETRANS-001.`,
    citations: [{ document_id: "SOP-NET-001", section_id: "SOP-NET-001#1" }],
    requires_human_review: ambiguous,
  };
}
