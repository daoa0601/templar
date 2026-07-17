import { createHash } from "node:crypto";

import type { IncidentInput } from "./contracts.js";
import { ANALYZER_VERSION, CORPUS_ID, POLICY_ID, POLICY_VERSION } from "./corpus.js";
import type { PcapAnalysis, PcapFact } from "./pcap-analyzer.js";
import { retransmissionPolicyFinding } from "./policy.js";

export type EvidenceSensitivity = "operational" | "sensitive" | "unknown";

export interface EvidenceItem<TFacts = unknown> {
  readonly evidence_id: string;
  readonly source_kind:
    "incident_input" | "structured_observation" | "ticket_reference" | "pcap_artifact";
  readonly sha256: `sha256:${string}`;
  readonly acquired_at: string | null;
  readonly context: Readonly<Record<string, string>>;
  readonly sensitivity: EvidenceSensitivity;
  readonly parser_version: string;
  readonly provenance: Readonly<Record<string, string | boolean>>;
  readonly facts: TFacts;
}

export interface Finding {
  readonly finding_id: string;
  readonly rule_id: string;
  readonly severity: string;
  readonly evidence_ids: ReadonlyArray<string>;
  readonly fact_ids: ReadonlyArray<string>;
  readonly statement: string;
  readonly citations: ReadonlyArray<{
    readonly document_id: string;
    readonly section_id: string;
  }>;
  readonly requires_human_review: boolean;
}

export interface Hypothesis {
  readonly hypothesis_id: string;
  readonly interpretation: string;
  readonly finding_ids: ReadonlyArray<string>;
  readonly confidence: "low" | "moderate" | "high";
  readonly alternatives: ReadonlyArray<string>;
  readonly unresolved_evidence_needs: ReadonlyArray<string>;
}

export interface EvidenceBundle {
  readonly schema_version: "1";
  readonly evidence_bundle_id: string;
  readonly evidence_items: ReadonlyArray<EvidenceItem>;
  readonly findings: ReadonlyArray<Finding>;
  readonly hypotheses: ReadonlyArray<Hypothesis>;
  readonly missing_information: ReadonlyArray<{
    readonly unknown_id: string;
    readonly description: string;
  }>;
  readonly provenance: {
    readonly corpus_id: typeof CORPUS_ID;
    readonly policy_id: typeof POLICY_ID;
    readonly policy_version: typeof POLICY_VERSION;
    readonly analyzer_version: typeof ANALYZER_VERSION;
  };
}

export interface EvaluationContext {
  readonly schema_version: "1";
  readonly known_evidence_ids: ReadonlyArray<string>;
  readonly known_fact_ids: ReadonlyArray<string>;
  readonly known_citations: ReadonlyArray<{
    readonly document_id: string;
    readonly section_id: string;
  }>;
  readonly known_rule_ids: ReadonlyArray<string>;
  readonly known_metrics: ReadonlyArray<{
    readonly fact_id: string;
    readonly metric: string;
    readonly value: number;
  }>;
  readonly expected_severity: string;
  readonly boundary_ambiguous: boolean;
  readonly required_evidence_ids: ReadonlyArray<string>;
  readonly required_action_ids: ReadonlyArray<string>;
  readonly required_unknown_ids: ReadonlyArray<string>;
  readonly allowed_actions: ReadonlyArray<{
    readonly action_id: string;
    readonly ordinal: number;
    readonly rule_id: string;
    readonly document_id: string;
    readonly section_id: string;
    readonly prerequisites: ReadonlyArray<string>;
  }>;
  readonly available_checks: ReadonlyArray<string>;
}

function digest(value: unknown): `sha256:${string}` {
  const encoded = typeof value === "string" ? value : JSON.stringify(value);
  return `sha256:${createHash("sha256").update(encoded).digest("hex")}`;
}

function incidentItems(incident: IncidentInput): ReadonlyArray<EvidenceItem> {
  const inputDigest = digest(incident);
  const request: EvidenceItem = {
    evidence_id: "evidence.incident.request",
    source_kind: "incident_input",
    sha256: inputDigest,
    acquired_at: null,
    context: { schema_version: incident.schema_version },
    sensitivity: "operational",
    parser_version: "incident-input-v1",
    provenance: { origin: "local_submission", caller_text_untrusted: true },
    facts: { request: incident.request, reported_priority: incident.reported_priority ?? null },
  };
  const observations: ReadonlyArray<EvidenceItem> = incident.observations.map((observation) => ({
    evidence_id: `evidence.observation.${observation.observation_id}`,
    source_kind: "structured_observation",
    sha256: inputDigest,
    acquired_at: null,
    context: { observation_id: observation.observation_id },
    sensitivity: "operational",
    parser_version: "incident-input-v1",
    provenance: { origin: "local_submission", caller_text_untrusted: true },
    facts: observation,
  }));
  const ticket: ReadonlyArray<EvidenceItem> =
    incident.ticket_ref === undefined
      ? []
      : [
          {
            evidence_id: "evidence.ticket.reference",
            source_kind: "ticket_reference",
            sha256: inputDigest,
            acquired_at: null,
            context: { connector_status: "not_configured" },
            sensitivity: "unknown",
            parser_version: "incident-input-v1",
            provenance: { origin: "untrusted_metadata", retrieved: false },
            facts: { ticket_ref: incident.ticket_ref },
          },
        ];
  return [request, ...observations, ...ticket];
}

function pcapItem(
  pcap: PcapAnalysis | undefined,
): ReadonlyArray<EvidenceItem<ReadonlyArray<PcapFact>>> {
  if (pcap === undefined) return [];
  const hash = pcap.artifact_id.slice("pcap_sha256_".length);
  return [
    {
      evidence_id: "evidence.pcap.capture",
      source_kind: "pcap_artifact",
      sha256: `sha256:${hash}`,
      acquired_at: null,
      context: { artifact_id: pcap.artifact_id },
      sensitivity: "operational",
      parser_version: pcap.analyzer_version,
      provenance: { origin: "local_content_addressed_store", digest_verified: true },
      facts: pcap.facts,
    },
  ];
}

export function buildEvidenceBundle(
  runId: string,
  incident: IncidentInput,
  pcap: PcapAnalysis | undefined,
): { readonly bundle: EvidenceBundle; readonly evaluation: EvaluationContext } {
  const evidenceItems = [...incidentItems(incident), ...pcapItem(pcap)];
  const findings: ReadonlyArray<Finding> =
    pcap === undefined
      ? []
      : [retransmissionPolicyFinding(pcap.metrics.tcp_retransmission_percent)];
  const missing = [
    {
      unknown_id: "unknown.interface_mapping",
      description: "Affected IPs are not mapped to physical interfaces.",
    },
    {
      unknown_id: "unknown.port_counters",
      description: "Physical error and drop counters have not been collected.",
    },
    {
      unknown_id: "unknown.qos_policy",
      description: "Applicable QoS policy state is not available.",
    },
  ];
  if (incident.ticket_ref !== undefined) {
    missing.push({
      unknown_id: "unknown.ticket_snapshot",
      description:
        "The untrusted ticket reference has not been retrieved by an approved connector.",
    });
  }
  const hypotheses: ReadonlyArray<Hypothesis> =
    findings.length === 0
      ? []
      : [
          {
            hypothesis_id: "hypothesis.retransmission_contributes_to_reported_impact",
            interpretation:
              "Observed TCP sequence reuse may contribute to the reported network impact.",
            finding_ids: [findings[0]!.finding_id],
            confidence: "low",
            alternatives: [
              "capture duplication",
              "upstream congestion",
              "physical errors",
              "QoS drops",
            ],
            unresolved_evidence_needs: missing.map((item) => item.unknown_id),
          },
        ];
  const severity = findings[0]?.severity ?? "none";
  const requiredActions = /packet|loss|retrans|congestion/iu.test(incident.request)
    ? ["sop.step.2.1", "sop.step.2.2", "sop.step.3"]
    : [];
  const factIds = pcap?.facts.map((fact) => fact.fact_id).sort() ?? [];
  const evidenceIds = evidenceItems.map((item) => item.evidence_id).sort();

  return {
    bundle: {
      schema_version: "1",
      evidence_bundle_id: `evidence-bundle-${runId}`,
      evidence_items: evidenceItems,
      findings,
      hypotheses,
      missing_information: missing,
      provenance: {
        corpus_id: CORPUS_ID,
        policy_id: POLICY_ID,
        policy_version: POLICY_VERSION,
        analyzer_version: ANALYZER_VERSION,
      },
    },
    evaluation: {
      schema_version: "1",
      known_evidence_ids: evidenceIds,
      known_fact_ids: factIds,
      known_citations: [
        { document_id: "HW-CFG-012", section_id: "HW-CFG-012#standard-port-configuration" },
        { document_id: "HW-CFG-012", section_id: "HW-CFG-012#verifying-dns-configuration" },
        { document_id: "SOP-NET-001", section_id: "SOP-NET-001#1" },
        { document_id: "SOP-NET-001", section_id: "SOP-NET-001#2" },
        { document_id: "SOP-NET-001", section_id: "SOP-NET-001#2.1" },
        { document_id: "SOP-NET-001", section_id: "SOP-NET-001#2.2" },
        { document_id: "SOP-NET-001", section_id: "SOP-NET-001#3" },
      ],
      known_rule_ids: [POLICY_ID],
      known_metrics:
        pcap === undefined
          ? []
          : [
              {
                fact_id: "fact.tcp.retransmissions",
                metric: "tcp_retransmission_percent",
                value: pcap.metrics.tcp_retransmission_percent,
              },
              {
                fact_id: "fact.tcp.retransmissions",
                metric: "tcp_retransmissions",
                value: pcap.metrics.tcp_retransmissions,
              },
              {
                fact_id: "fact.tcp.retransmissions",
                metric: "tcp_packets",
                value: pcap.metrics.tcp_packets,
              },
            ],
      expected_severity: severity,
      boundary_ambiguous: severity === "boundary_ambiguous",
      required_evidence_ids: evidenceIds,
      required_action_ids: requiredActions,
      required_unknown_ids: missing.map((item) => item.unknown_id).sort(),
      allowed_actions: [
        {
          action_id: "sop.step.2.1",
          ordinal: 1,
          rule_id: POLICY_ID,
          document_id: "SOP-NET-001",
          section_id: "SOP-NET-001#2.1",
          prerequisites: [],
        },
        {
          action_id: "sop.step.2.2",
          ordinal: 2,
          rule_id: POLICY_ID,
          document_id: "SOP-NET-001",
          section_id: "SOP-NET-001#2.2",
          prerequisites: ["sop.step.2.1"],
        },
        {
          action_id: "sop.step.3",
          ordinal: 3,
          rule_id: POLICY_ID,
          document_id: "SOP-NET-001",
          section_id: "SOP-NET-001#3",
          prerequisites: ["sop.step.2.2"],
        },
      ],
      available_checks: ["incident_input", ...(pcap === undefined ? [] : ["pcap_analysis"])],
    },
  };
}
