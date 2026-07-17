import type { PcapAnalysis } from "./pcap-analyzer.js";

export interface PcapSecurityObservation {
  readonly observation_id: string;
  readonly fact_id: string;
  readonly kind: string;
  readonly value: unknown;
}

export interface PcapSecurityEvidence {
  readonly schema_version: "1";
  readonly evidence_id: "evidence.pcap.capture";
  readonly artifact_id: string;
  readonly analyzer_version: string;
  readonly observations: ReadonlyArray<PcapSecurityObservation>;
}

export interface PcapSecurityEvaluationContext {
  readonly schema_version: "1";
  readonly known_observation_ids: ReadonlyArray<string>;
  readonly required_observation_ids: ReadonlyArray<string>;
  readonly known_principle_ids: ReadonlyArray<string>;
  readonly known_unknown_ids: ReadonlyArray<string>;
  readonly required_unknown_ids: ReadonlyArray<string>;
  readonly allowed_actions: ReadonlyArray<{
    readonly action_id: string;
    readonly ordinal: number;
  }>;
  readonly available_checks: ReadonlyArray<string>;
}

export const PCAP_SECURITY_PLAYBOOK = {
  schema_version: "1",
  playbook_id: "pcap-security-triage-v1",
  principles: [
    {
      principle_id: "principle.facts_are_not_verdicts",
      statement:
        "Packet observations may support hypotheses, but do not by themselves prove compromise, execution, malware family, or actor attribution.",
    },
    {
      principle_id: "principle.alternatives_required",
      statement:
        "Every security hypothesis must name plausible benign or operational alternatives and the evidence needed to distinguish them.",
    },
    {
      principle_id: "principle.endpoint_context_required",
      statement:
        "PCAP data cannot establish endpoint process, user, persistence, or authorization state; correlate with host and identity telemetry.",
    },
    {
      principle_id: "principle.passive_only",
      statement:
        "Triage may preserve, correlate, baseline, and escalate supplied evidence but may not probe, replay, scan, exploit, or change systems.",
    },
  ],
  unknowns: [
    {
      unknown_id: "unknown.endpoint_process_context",
      description: "The process responsible for observed traffic is not available in the PCAP.",
    },
    {
      unknown_id: "unknown.asset_role_and_owner",
      description: "The intended role and owner of observed endpoints are not established.",
    },
    {
      unknown_id: "unknown.identity_context",
      description: "Authentication and user-session context is not present in packet summaries.",
    },
    {
      unknown_id: "unknown.network_baseline",
      description: "No environment-specific baseline is available for comparison.",
    },
    {
      unknown_id: "unknown.capture_completeness",
      description: "Capture position, filters, loss, NAT, and asymmetric routing remain unknown.",
    },
  ],
  actions: [
    {
      action_id: "action.preserve_capture",
      ordinal: 1,
      description: "Preserve the staged capture and analysis result for authorized follow-up.",
    },
    {
      action_id: "action.validate_asset_role",
      ordinal: 2,
      description:
        "Confirm whether the observed services and peers match the asset's intended role.",
    },
    {
      action_id: "action.correlate_endpoint_telemetry",
      ordinal: 3,
      description:
        "Correlate the time window with authorized process, EDR, and host-event telemetry.",
    },
    {
      action_id: "action.review_identity_activity",
      ordinal: 4,
      description:
        "Review authorized authentication and session evidence for the observed endpoints.",
    },
    {
      action_id: "action.compare_network_baseline",
      ordinal: 5,
      description: "Compare the pattern with an approved environment-specific network baseline.",
    },
  ],
} as const;

const REQUIRED_FACT_IDS = [
  "fact.capture.metadata",
  "fact.protocol.counts",
  "fact.ipv4.top_talkers",
  "fact.transport.destination_ports",
  "fact.transport.source_profiles",
  "fact.transport.conversations",
  "fact.tcp.flags",
  "fact.dns.qr_counts",
] as const;

function observationId(factId: string): string {
  return `observation.${factId.startsWith("fact.") ? factId.slice(5) : factId}`;
}

export function buildPcapSecurityEvidence(pcap: PcapAnalysis): {
  readonly evidence: PcapSecurityEvidence;
  readonly evaluation: PcapSecurityEvaluationContext;
} {
  const observations = pcap.facts.map((fact) => ({
    observation_id: observationId(fact.fact_id),
    fact_id: fact.fact_id,
    kind: fact.kind,
    value: fact.value,
  }));
  const byFactId = new Map(observations.map((observation) => [observation.fact_id, observation]));
  const knownObservationIds = observations.map((observation) => observation.observation_id).sort();
  const requiredObservationIds = REQUIRED_FACT_IDS.flatMap((factId) => {
    const observation = byFactId.get(factId);
    return observation === undefined ? [] : [observation.observation_id];
  });
  const knownUnknownIds = PCAP_SECURITY_PLAYBOOK.unknowns.map((item) => item.unknown_id);

  return {
    evidence: {
      schema_version: "1",
      evidence_id: "evidence.pcap.capture",
      artifact_id: pcap.artifact_id,
      analyzer_version: pcap.analyzer_version,
      observations,
    },
    evaluation: {
      schema_version: "1",
      known_observation_ids: knownObservationIds,
      required_observation_ids: requiredObservationIds,
      known_principle_ids: PCAP_SECURITY_PLAYBOOK.principles.map(
        (principle) => principle.principle_id,
      ),
      known_unknown_ids: knownUnknownIds,
      required_unknown_ids: knownUnknownIds,
      allowed_actions: PCAP_SECURITY_PLAYBOOK.actions.map(({ action_id, ordinal }) => ({
        action_id,
        ordinal,
      })),
      available_checks: ["pcap_analysis"],
    },
  };
}
