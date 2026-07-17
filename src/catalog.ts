import { invalidInput } from "./errors.js";

export const CAPABILITY_CLASSES = [
  "PASSIVE_READ",
  "DEFENSIVE_ADVICE",
  "RE_STATIC",
  "RE_DYNAMIC_LAB",
  "ACTIVE_TEST",
] as const;

export type CapabilityClass = (typeof CAPABILITY_CLASSES)[number];
export type WorkflowFamily =
  "network_analysis" | "blue_team" | "reverse_engineering" | "threat_intelligence" | "red_team";
export type WorkflowReleaseState = "enabled" | "planned" | "requires_lab" | "disabled";
export type NetworkMode =
  "denied" | "approved_passive_queries" | "lab_simulated_or_allowlisted" | "roe_target_allowlist";
export type FilesystemMode =
  | "read_only_evidence"
  | "isolated_candidate_worktree"
  | "egress_denied_parser_sandbox"
  | "disposable_lab"
  | "isolated_active_lab";

export interface WorkflowBudgets {
  readonly wallClockSeconds: number;
  readonly maxTurns: number;
  readonly maxTokens: number;
  readonly maxConcurrency: number;
  readonly maxOutputBytes: number;
}

export interface WorkflowCatalogEntry {
  readonly id: string;
  readonly version: string;
  readonly family: WorkflowFamily;
  readonly description: string;
  readonly inputSchemaId: string;
  readonly outputSchemaId: string;
  readonly requiredCapability: CapabilityClass;
  readonly authorizationCheckpoint: string;
  readonly networkMode: NetworkMode;
  readonly filesystemMode: FilesystemMode;
  readonly toolAllowlist: ReadonlyArray<string>;
  readonly budgets: WorkflowBudgets;
  readonly evaluatorRequired: boolean;
  readonly traceAuditorRequired: boolean;
  readonly persistencePolicy: "bounded_case_record" | "quarantined_lab_record" | "none";
  readonly dataSensitivityPolicy: "operational" | "sensitive_quarantine" | "roe_scoped";
  readonly releaseState: WorkflowReleaseState;
  /** Compatibility projection; releaseState is the authoritative gate. */
  readonly enabledByDefault: boolean;
}

const PASSIVE_BUDGET: WorkflowBudgets = {
  wallClockSeconds: 300,
  maxTurns: 5,
  maxTokens: 12_000,
  maxConcurrency: 2,
  maxOutputBytes: 2 * 1024 * 1024,
};

const TELECOM_INCIDENT_BUDGET: WorkflowBudgets = {
  ...PASSIVE_BUDGET,
  // Charges fresh (non-cached) input and output for each supervisor,
  // candidate, and independent audit turn; time and output remain bounded too.
  wallClockSeconds: 600,
  maxTokens: 500_000,
};

const PCAP_SECURITY_TRIAGE_BUDGET: WorkflowBudgets = {
  ...PASSIVE_BUDGET,
  maxTokens: 300_000,
};

const EXERCISE_SOLVE_BUDGET: WorkflowBudgets = {
  ...PASSIVE_BUDGET,
  wallClockSeconds: 600,
  maxTurns: 3,
  maxTokens: 300_000,
};

const STATIC_BUDGET: WorkflowBudgets = {
  wallClockSeconds: 600,
  maxTurns: 4,
  maxTokens: 16_000,
  maxConcurrency: 1,
  maxOutputBytes: 8 * 1024 * 1024,
};

const LAB_BUDGET: WorkflowBudgets = {
  wallClockSeconds: 900,
  maxTurns: 4,
  maxTokens: 16_000,
  maxConcurrency: 1,
  maxOutputBytes: 32 * 1024 * 1024,
};

function entry(options: Omit<WorkflowCatalogEntry, "enabledByDefault">): WorkflowCatalogEntry {
  return { ...options, enabledByDefault: options.releaseState === "enabled" };
}

function plannedPassive(
  id: string,
  description: string,
  family: WorkflowFamily = "blue_team",
  requiredCapability: CapabilityClass = "PASSIVE_READ",
): WorkflowCatalogEntry {
  return entry({
    id,
    version: "0.1.0",
    family,
    description,
    inputSchemaId: `templar://${id}/input/v1`,
    outputSchemaId: `templar://${id}/output/v1`,
    requiredCapability,
    authorizationCheckpoint: "case_scope_and_data_policy",
    networkMode: "denied",
    filesystemMode: "read_only_evidence",
    toolAllowlist: [],
    budgets: PASSIVE_BUDGET,
    evaluatorRequired: true,
    traceAuditorRequired: true,
    persistencePolicy: "bounded_case_record",
    dataSensitivityPolicy: "operational",
    releaseState: "planned",
  });
}

export const WORKFLOW_CATALOG: ReadonlyArray<WorkflowCatalogEntry> = [
  entry({
    id: "telecom_incident",
    version: "1.0.0",
    family: "network_analysis",
    description: "Bounded packet and network incident evidence review with advisory actions.",
    inputSchemaId: "templar://telecom_incident/IncidentInput/v1",
    outputSchemaId: "templar://telecom_incident/IncidentRunResult/v1",
    requiredCapability: "PASSIVE_READ",
    authorizationCheckpoint: "local_case_scope",
    networkMode: "denied",
    filesystemMode: "isolated_candidate_worktree",
    toolAllowlist: ["analyze_classic_pcap", "read_versioned_corpus"],
    budgets: TELECOM_INCIDENT_BUDGET,
    evaluatorRequired: true,
    traceAuditorRequired: true,
    persistencePolicy: "bounded_case_record",
    dataSensitivityPolicy: "operational",
    releaseState: "enabled",
  }),
  entry({
    id: "pcap_security_triage",
    version: "1.0.0",
    family: "blue_team",
    description: "Passive security triage of one locally staged classic PCAP.",
    inputSchemaId: "templar://pcap_security_triage/PcapSecurityTriageInput/v1",
    outputSchemaId: "templar://pcap_security_triage/PcapSecurityTriageResult/v1",
    requiredCapability: "PASSIVE_READ",
    authorizationCheckpoint: "local_capture_scope",
    networkMode: "denied",
    filesystemMode: "isolated_candidate_worktree",
    toolAllowlist: ["analyze_classic_pcap"],
    budgets: PCAP_SECURITY_TRIAGE_BUDGET,
    evaluatorRequired: true,
    traceAuditorRequired: false,
    persistencePolicy: "bounded_case_record",
    dataSensitivityPolicy: "operational",
    releaseState: "enabled",
  }),
  entry({
    id: "exercise_solve",
    version: "1.0.0",
    family: "reverse_engineering",
    description: "Solve a bounded static-analysis exercise from a precomputed evidence snapshot.",
    inputSchemaId: "templar://exercise_solve/ExerciseSolveInput/v1",
    outputSchemaId: "templar://exercise_solve/ExerciseCandidateResult/v1",
    requiredCapability: "RE_STATIC",
    authorizationCheckpoint: "local_static_exercise_scope",
    networkMode: "denied",
    filesystemMode: "isolated_candidate_worktree",
    toolAllowlist: [],
    budgets: EXERCISE_SOLVE_BUDGET,
    evaluatorRequired: true,
    traceAuditorRequired: false,
    persistencePolicy: "bounded_case_record",
    dataSensitivityPolicy: "operational",
    releaseState: "enabled",
  }),
  plannedPassive(
    "case.authorize",
    "Validate case ownership, scope, sensitivity, grants, approvals, and expiry.",
  ),
  plannedPassive(
    "evidence.register",
    "Hash, classify, and immutably register supplied evidence and provenance.",
  ),
  plannedPassive(
    "incident.reconstruct",
    "Build a cited host, network, and identity timeline with competing hypotheses.",
  ),
  plannedPassive(
    "host.artifact_triage",
    "Correlate supplied process, registry, service, file, log, and network artifacts.",
  ),
  entry({
    ...plannedPassive(
      "binary.static_pe",
      "No-execution PE structural triage.",
      "reverse_engineering",
      "RE_STATIC",
    ),
    filesystemMode: "egress_denied_parser_sandbox",
    budgets: STATIC_BUDGET,
    toolAllowlist: ["parse_pe_static"],
  }),
  entry({
    ...plannedPassive(
      "binary.static_dotnet",
      "No-execution assembly, metadata, CIL, and reference triage.",
      "reverse_engineering",
      "RE_STATIC",
    ),
    filesystemMode: "egress_denied_parser_sandbox",
    budgets: STATIC_BUDGET,
    toolAllowlist: ["parse_dotnet_static"],
  }),
  entry({
    ...plannedPassive(
      "intel.ioc_graph",
      "Build source- and time-aware passive IOC relationships with false-flag alternatives.",
      "threat_intelligence",
    ),
    networkMode: "approved_passive_queries",
    toolAllowlist: ["approved_passive_lookup"],
  }),
  plannedPassive(
    "detection.rule_draft",
    "Draft and synthetically evaluate cited detection rules.",
    "blue_team",
    "DEFENSIVE_ADVICE",
  ),
  plannedPassive(
    "containment.advise",
    "Produce cited reversible containment guidance with side effects; never execute it.",
    "blue_team",
    "DEFENSIVE_ADVICE",
  ),
  plannedPassive(
    "dynamic.plan",
    "Define hypotheses, instrumentation, lab requirements, stop conditions, and expected evidence.",
    "reverse_engineering",
  ),
  ...[
    [
      "sample.dynamic_observe",
      "Controlled runtime observation in a disposable lab.",
      ["observe_process", "observe_filesystem", "observe_registry", "observe_simulated_network"],
    ],
    [
      "sample.debug_unpack",
      "Debugging, memory capture, unpacking, and payload recovery in quarantine.",
      ["debug_sample", "capture_memory", "recover_payload"],
    ],
    [
      "sample.dotnet_runtime",
      "Controlled CLR, ETW, AMSI, heap, and dynamic assembly observation.",
      ["observe_clr", "capture_dynamic_assembly"],
    ],
    [
      "network.c2_emulate",
      "Controlled fake services for narrowly scoped behavior questions.",
      ["simulate_allowlisted_service"],
    ],
  ].map(([id, description, tools]) =>
    entry({
      id: id as string,
      version: "0.1.0",
      family: "reverse_engineering",
      description: description as string,
      inputSchemaId: `templar://${id as string}/input/v1`,
      outputSchemaId: `templar://${id as string}/output/v1`,
      requiredCapability: "RE_DYNAMIC_LAB",
      authorizationCheckpoint: "attested_lab_and_human_approval",
      networkMode: "lab_simulated_or_allowlisted",
      filesystemMode: "disposable_lab",
      toolAllowlist: tools as ReadonlyArray<string>,
      budgets: LAB_BUDGET,
      evaluatorRequired: true,
      traceAuditorRequired: true,
      persistencePolicy: "quarantined_lab_record",
      dataSensitivityPolicy: "sensitive_quarantine",
      releaseState: "requires_lab",
    }),
  ),
  entry({
    id: "redteam.exercise",
    version: "0.1.0",
    family: "red_team",
    description:
      "Separate active-testing subsystem constrained to verified written rules of engagement.",
    inputSchemaId: "templar://redteam.exercise/input/v1",
    outputSchemaId: "templar://redteam.exercise/output/v1",
    requiredCapability: "ACTIVE_TEST",
    authorizationCheckpoint: "verified_written_roe_and_immediate_human_approval",
    networkMode: "roe_target_allowlist",
    filesystemMode: "isolated_active_lab",
    toolAllowlist: [],
    budgets: LAB_BUDGET,
    evaluatorRequired: true,
    traceAuditorRequired: true,
    persistencePolicy: "quarantined_lab_record",
    dataSensitivityPolicy: "roe_scoped",
    releaseState: "disabled",
  }),
];

export interface WrittenRulesOfEngagement {
  readonly engagementId: string;
  readonly legalGrantor: string;
  readonly targetAllowlist: ReadonlyArray<string>;
  readonly methodAllowlist: ReadonlyArray<string>;
  readonly exclusions: ReadonlyArray<string>;
  readonly startsAt: string;
  readonly expiresAt: string;
  readonly emergencyContact: string;
  readonly killSwitchConfirmed: boolean;
}

export interface WorkflowAuthorizationPolicy {
  readonly grantedCapabilities?: ReadonlyArray<CapabilityClass>;
  readonly labAttested?: boolean;
  readonly humanApproved?: boolean;
  readonly enableDisabledWorkflow?: boolean;
  readonly writtenRoe?: WrittenRulesOfEngagement;
}

export interface WorkflowAdmission {
  readonly allowed: boolean;
  readonly reasons: ReadonlyArray<string>;
}

export function workflowEntry(workflowId: string): WorkflowCatalogEntry {
  const found = WORKFLOW_CATALOG.find((candidate) => candidate.id === workflowId);
  if (found === undefined) throw invalidInput(`Unknown Templar workflow: ${workflowId}.`);
  return found;
}

function validRoe(roe: WrittenRulesOfEngagement | undefined): boolean {
  if (roe === undefined) return false;
  const starts = Date.parse(roe.startsAt);
  const expires = Date.parse(roe.expiresAt);
  return (
    roe.engagementId.trim().length > 0 &&
    roe.legalGrantor.trim().length > 0 &&
    roe.targetAllowlist.length > 0 &&
    roe.methodAllowlist.length > 0 &&
    roe.exclusions.length > 0 &&
    roe.emergencyContact.trim().length > 0 &&
    roe.killSwitchConfirmed &&
    Number.isFinite(starts) &&
    Number.isFinite(expires) &&
    starts < expires &&
    Date.now() >= starts &&
    Date.now() < expires
  );
}

export function workflowAdmission(
  catalogEntry: WorkflowCatalogEntry,
  policy: WorkflowAuthorizationPolicy = {},
): WorkflowAdmission {
  const reasons: Array<string> = [];
  const grants = new Set(policy.grantedCapabilities ?? ["PASSIVE_READ"]);
  if (!grants.has(catalogEntry.requiredCapability)) reasons.push("required_capability_missing");
  if (catalogEntry.releaseState === "planned") reasons.push("workflow_not_released");
  if (catalogEntry.requiredCapability === "RE_DYNAMIC_LAB") {
    if (policy.labAttested !== true) reasons.push("lab_attestation_missing");
    if (policy.humanApproved !== true) reasons.push("human_approval_missing");
  }
  if (catalogEntry.requiredCapability === "ACTIVE_TEST") {
    if (policy.enableDisabledWorkflow !== true) reasons.push("active_testing_disabled");
    if (!validRoe(policy.writtenRoe)) reasons.push("verified_written_roe_missing");
    if (policy.labAttested !== true) reasons.push("lab_attestation_missing");
    if (policy.humanApproved !== true) reasons.push("human_approval_missing");
  } else if (catalogEntry.releaseState === "disabled") {
    reasons.push("workflow_disabled");
  }
  return { allowed: reasons.length === 0, reasons: [...new Set(reasons)].sort() };
}

export function assertWorkflowAuthorized(
  catalogEntry: WorkflowCatalogEntry,
  policy: WorkflowAuthorizationPolicy = {},
): void {
  const admission = workflowAdmission(catalogEntry, policy);
  if (!admission.allowed) {
    throw invalidInput(
      `Templar workflow ${catalogEntry.id} is not authorized: ${admission.reasons.join(", ")}.`,
    );
  }
}

export function requiresHumanAcknowledgment(options: {
  readonly family: WorkflowFamily;
  readonly severity?: string;
  readonly highImpact?: boolean;
  readonly securityOutcome?: boolean;
  readonly headlineResult?: boolean;
  readonly manualAuditRequired?: boolean;
}): ReadonlyArray<string> {
  const reasons: Array<string> = [];
  if (options.family === "red_team") reasons.push("active_security_result");
  if (options.severity === "high" || options.highImpact === true)
    reasons.push("high_impact_result");
  if (options.securityOutcome === true) reasons.push("security_result");
  if (options.headlineResult === true) reasons.push("headline_result");
  if (options.manualAuditRequired === true) reasons.push("manual_evaluation_audit");
  return [...new Set(reasons)];
}
