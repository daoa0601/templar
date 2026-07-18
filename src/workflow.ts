import type { WorkflowDefinition } from "@agentic-orch/agent-blocks/templates/scoped-worktree";

import type {
  ExerciseSolveWorkspace,
  PcapSecurityTriageWorkspace,
  SourceSecurityAuditWorkspace,
  SourceSecurityFixWorkspace,
  TelecomIncidentWorkspace,
} from "./workspace.js";
import {
  COURSE_SECURITY_EVALUATION_TEAM_PLAN,
  PCAP_SECURITY_TRIAGE_TEAM_PLAN,
  rolesForSecurityTeamPlan,
  securityRoleAssignment,
  SOURCE_SECURITY_AUDIT_TEAM_PLAN,
  SOURCE_SECURITY_FIX_TEAM_PLAN,
} from "./security-teams.js";

export const TELECOM_WORKFLOW_LIMITS = {
  maxRounds: 4,
  maxConcurrentAgents: 2,
  maxTotalAgents: 5,
  maxTotalAgentTurns: 5,
  maxWallClockSeconds: 600,
  turnTimeoutSeconds: 180,
  // The harness charges fresh (non-cached) input plus output. The bounded
  // four-round workflow needs headroom for nine schema-constrained turns while
  // per-turn and wall-clock limits separately bound cached tool loops.
  maxTotalTokens: 500_000,
} as const;

export const PCAP_SECURITY_TRIAGE_WORKFLOW_LIMITS = {
  maxRounds: 3,
  maxConcurrentAgents: 2,
  maxTotalAgents: 3,
  maxTotalAgentTurns: 3,
  maxWallClockSeconds: 300,
  turnTimeoutSeconds: 120,
  maxTotalTokens: 300_000,
} as const;

export const EXERCISE_SOLVE_WORKFLOW_LIMITS = {
  maxRounds: 3,
  maxConcurrentAgents: 2,
  maxTotalAgents: 3,
  maxTotalAgentTurns: 3,
  maxWallClockSeconds: 600,
  turnTimeoutSeconds: 180,
  maxTotalTokens: 300_000,
} as const;

export const COURSE_SECURITY_EVALUATION_WORKFLOW_LIMITS = {
  maxRounds: 5,
  maxConcurrentAgents: 4,
  maxTotalAgents: 9,
  maxTotalAgentTurns: 9,
  maxWallClockSeconds: 3_600,
  turnTimeoutSeconds: 600,
  maxTotalTokens: 1_500_000,
} as const;

export const SOURCE_SECURITY_AUDIT_WORKFLOW_LIMITS = {
  maxRounds: 5,
  maxConcurrentAgents: 3,
  maxTotalAgents: 8,
  maxTotalAgentTurns: 8,
  maxWallClockSeconds: 1_200,
  turnTimeoutSeconds: 240,
  maxTotalTokens: 800_000,
} as const;

export const SOURCE_SECURITY_FIX_WORKFLOW_LIMITS = {
  maxRounds: 4,
  maxConcurrentAgents: 2,
  maxTotalAgents: 5,
  maxTotalAgentTurns: 5,
  maxWallClockSeconds: 900,
  turnTimeoutSeconds: 240,
  maxTotalTokens: 600_000,
} as const;

export function telecomIncidentWorkflow(incident: TelecomIncidentWorkspace): WorkflowDefinition {
  return {
    version: 1,
    name: "telecom_incident",
    objective:
      "Produce a cited, evaluator-checked network incident result from the immutable local evidence bundle.",
    configPath: `${incident.root}/workflow.json`,
    workspace: incident.root,
    allowDirtyWorkspace: false,
    supervisor: {
      model: undefined,
      instructions: `Use this exact bounded sequence and no other sequence:
Round 1: assign research_once to role evidence_researcher. It identifies applicable evidence,
rules, and missing facts only.
Round 2: after research completes, assign candidate_a and candidate_b together to role
diagnosis_candidate. They are independent and each writes only result.json and report.md.
Round 3: after both candidate snapshots and independent evaluator outputs exist, assign audit_a to
candidate_a and audit_b to candidate_b using role evaluation_auditor and the corresponding
targetCandidateId. Auditors inspect only, rerun the evaluator, and never select.
Round 4: accept the highest scoring evaluator-passing candidate. Break an exact score tie by
candidate ordinal (candidate_a before candidate_b). If neither candidate passes, stop. Never accept
an evaluator failure, skip a phase, dispatch an undeclared agent, change scope, or ask for more turns.`,
    },
    roles: [
      {
        id: "evidence_researcher",
        kind: "research",
        description: "Read-only evidence and rule applicability research.",
        instructions:
          "Read incident.json, evidence.json, the versioned corpus and policy. Identify applicable IDs and missing facts. Do not edit, use network, invoke external services, or spawn agents.",
        maxInstances: 1,
        maxTurns: 1,
        model: undefined,
      },
      {
        id: "diagnosis_candidate",
        kind: "candidate",
        description: "Independent structured network incident diagnosis writer.",
        instructions:
          "Follow CANDIDATE_INSTRUCTIONS.md. Write result.json and report.md only. Use existing evidence, document, section, rule, action, and unknown IDs. Do not use network, external tools, or mutate external systems.",
        maxInstances: 2,
        maxTurns: 1,
        model: undefined,
      },
      {
        id: "evaluation_auditor",
        kind: "review",
        description: "Independent read-only evaluation audit of one pinned candidate.",
        instructions: `Inspect final result.json and report.md, the evaluator contract/output, Git
diff, and the candidate-scoped .harness-audit/trace.jsonl when present. Rerun
node evaluation/evaluate.mjs without editing. Explicitly look for hardcoded outputs, cache reuse,
test/grader detection, environment or path tricks, unsupported claims, and benchmark/evidence
gaming. If trace.jsonl is absent, state that audit coverage is degraded and set manual audit
required. In the AgentReport evidence array emit these control entries as separate strings with
exact values and no suffix or commentary:
audit.checks_rerun=deterministic_evaluator,evaluator_contract,git_diff
audit.trace_inspected=true|false
audit.trace_complete=true|false
audit.suspicious_behavior=none (or a comma-separated list)
audit.disposition=pass|manual_review
audit.manualAuditRequired=false|true
Put explanatory detail only in separate audit.finding=<text> entries. Read the
trace header: if it reports truncated=true or any records were omitted, set trace_complete=false,
disposition=manual_review, and manualAuditRequired=true. Never edit, use network, select a candidate,
or broaden scope.`,
        maxInstances: 2,
        maxTurns: 1,
        model: undefined,
      },
    ],
    limits: TELECOM_WORKFLOW_LIMITS,
    evaluation: {
      command: ["node", incident.evaluatorPath],
      timeoutSeconds: 20,
    },
    codex: {
      binary: "codex",
      ignoreUserConfig: true,
      maxOutputBytes: 2 * 1024 * 1024,
    },
  };
}

export function pcapSecurityTriageWorkflow(
  triage: PcapSecurityTriageWorkspace,
): WorkflowDefinition {
  const evidenceCoordinator = securityRoleAssignment(
    PCAP_SECURITY_TRIAGE_TEAM_PLAN,
    "pcap_evidence_research",
  );
  const analystA = securityRoleAssignment(PCAP_SECURITY_TRIAGE_TEAM_PLAN, "pcap_triage_a");
  const analystB = securityRoleAssignment(PCAP_SECURITY_TRIAGE_TEAM_PLAN, "pcap_triage_b");
  return {
    version: 1,
    name: "pcap_security_triage",
    objective:
      "Produce a passive security triage report from bounded local PCAP facts without claiming unsupported compromise or attribution.",
    configPath: `${triage.root}/workflow.json`,
    workspace: triage.root,
    allowDirtyWorkspace: false,
    supervisor: {
      model: undefined,
      instructions: `Use this exact bounded sequence and no other sequence:
Round 1: assign ${evidenceCoordinator.block.agentId} to role ${evidenceCoordinator.block.role.id}. It identifies the most relevant
packet observations, uncertainty, plausible alternatives, and applicable playbook principles only.
Round 2: after research completes, assign ${analystA.block.agentId} and ${analystB.block.agentId} together to role
${analystA.block.role.id}. Include the researcher's relevant observation IDs and gaps in both tasks. The two
analysts remain independent and each writes only result.json and report.md.
Round 3: accept the highest scoring evaluator-passing candidate. Break an exact score tie by
candidate ordinal (${analystA.block.agentId} before ${analystB.block.agentId}). If neither passes, stop. Never add a reviewer
round, skip the research phase, dispatch an undeclared agent, change scope, or ask for more turns.`,
    },
    roles: rolesForSecurityTeamPlan(PCAP_SECURITY_TRIAGE_TEAM_PLAN),
    limits: PCAP_SECURITY_TRIAGE_WORKFLOW_LIMITS,
    evaluation: {
      command: ["node", triage.evaluatorPath],
      timeoutSeconds: 20,
    },
    codex: {
      binary: "codex",
      ignoreUserConfig: true,
      maxOutputBytes: 2 * 1024 * 1024,
    },
  };
}

export function exerciseSolveWorkflow(exercise: ExerciseSolveWorkspace): WorkflowDefinition {
  return {
    version: 1,
    name: "exercise_solve",
    objective:
      "Answer every bounded static-analysis exercise question from supplied analyzer observations without executing the artifact or using external lookup.",
    configPath: `${exercise.root}/workflow.json`,
    workspace: exercise.root,
    allowDirtyWorkspace: false,
    supervisor: {
      model: undefined,
      instructions: `Use this exact bounded sequence and no other sequence:
Round 1: assign research_once to role exercise_researcher. It maps every question to relevant
observation IDs, identifies calculations that can be reproduced from the evidence, and names gaps.
Round 2: after research completes, assign candidate_a and candidate_b together to role
exercise_solver. Include the researcher's question-to-observation map in both tasks. The two solvers
remain independent and each writes only result.json and report.md.
Round 3: accept the highest scoring evaluator-passing candidate. Break an exact score tie by
candidate ordinal (candidate_a before candidate_b). If neither passes, stop. Never add a reviewer
round, skip research, dispatch an undeclared agent, execute the artifact, or ask for more turns.`,
    },
    roles: [
      {
        id: "exercise_researcher",
        kind: "research",
        description: "Read-only mapping from exercise questions to static analyzer observations.",
        instructions:
          "Read exercise.json and evaluation/context.json. Map all question IDs to relevant observation IDs, identify reproducible calculations, and state gaps. Do not edit, use network, execute content, open host paths, or spawn agents.",
        maxInstances: 1,
        maxTurns: 1,
        model: undefined,
      },
      {
        id: "exercise_solver",
        kind: "candidate",
        description: "Independent grounded solver for a bounded static-analysis exercise.",
        instructions:
          "Follow CANDIDATE_INSTRUCTIONS.md. Answer every question from the supplied analyzer text, cite observation IDs, show concise justification, and write only result.json and report.md. Do not use network, execute content, or mutate external systems.",
        maxInstances: 2,
        maxTurns: 1,
        model: undefined,
      },
    ],
    limits: EXERCISE_SOLVE_WORKFLOW_LIMITS,
    evaluation: {
      command: ["node", exercise.evaluatorPath],
      timeoutSeconds: 20,
    },
    codex: {
      binary: "codex",
      ignoreUserConfig: true,
      maxOutputBytes: 2 * 1024 * 1024,
    },
  };
}

export function courseSecurityEvaluationWorkflow(
  exercise: ExerciseSolveWorkspace,
  options: { readonly model?: string } = {},
): WorkflowDefinition {
  const model = options.model?.trim();
  if (
    model !== undefined &&
    (model.length === 0 ||
      model.length > 128 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/[\]-]{0,127}$/u.test(model))
  ) {
    throw new Error("The course evaluation model identifier is invalid.");
  }
  const coordinator = securityRoleAssignment(
    COURSE_SECURITY_EVALUATION_TEAM_PLAN,
    "course_evidence_map",
  );
  const windows = securityRoleAssignment(
    COURSE_SECURITY_EVALUATION_TEAM_PLAN,
    "course_windows_intrusion_analysis",
  );
  const native = securityRoleAssignment(
    COURSE_SECURITY_EVALUATION_TEAM_PLAN,
    "course_native_re_analysis",
  );
  const managed = securityRoleAssignment(
    COURSE_SECURITY_EVALUATION_TEAM_PLAN,
    "course_managed_re_analysis",
  );
  const batch = securityRoleAssignment(
    COURSE_SECURITY_EVALUATION_TEAM_PLAN,
    "course_batch_re_analysis",
  );
  const solverA = securityRoleAssignment(COURSE_SECURITY_EVALUATION_TEAM_PLAN, "course_solution_a");
  const solverB = securityRoleAssignment(COURSE_SECURITY_EVALUATION_TEAM_PLAN, "course_solution_b");
  const auditorA = securityRoleAssignment(
    COURSE_SECURITY_EVALUATION_TEAM_PLAN,
    "course_evaluation_audit_a",
  );
  const auditorB = securityRoleAssignment(
    COURSE_SECURITY_EVALUATION_TEAM_PLAN,
    "course_evaluation_audit_b",
  );
  return {
    version: 1,
    name: "course_security_evaluation",
    objective:
      "Solve every requirement in the versioned security course corpus from passive, content-identified evidence with independent falsification and assurance.",
    configPath: `${exercise.root}/workflow.json`,
    workspace: exercise.root,
    allowDirtyWorkspace: false,
    supervisor: {
      model,
      instructions: `Use this exact bounded sequence and no other sequence:
The identity tuples below are literal control-plane values. Copy agentId, roleId, and
targetCandidateId exactly; an agentId is not a roleId and must never be derived or renamed:
Round 1 identities: [{"agentId":"${coordinator.block.agentId}","roleId":"${coordinator.block.role.id}","targetCandidateId":null}]
Round 2 identities: [{"agentId":"${windows.block.agentId}","roleId":"${windows.block.role.id}","targetCandidateId":null},{"agentId":"${native.block.agentId}","roleId":"${native.block.role.id}","targetCandidateId":null},{"agentId":"${managed.block.agentId}","roleId":"${managed.block.role.id}","targetCandidateId":null},{"agentId":"${batch.block.agentId}","roleId":"${batch.block.role.id}","targetCandidateId":null}]
Round 3 identities: [{"agentId":"${solverA.block.agentId}","roleId":"${solverA.block.role.id}","targetCandidateId":null},{"agentId":"${solverB.block.agentId}","roleId":"${solverB.block.role.id}","targetCandidateId":null}]
Round 4 identities: [{"agentId":"${auditorA.block.agentId}","roleId":"${auditorA.block.role.id}","targetCandidateId":"${auditorA.block.targetCandidateId}"},{"agentId":"${auditorB.block.agentId}","roleId":"${auditorB.block.role.id}","targetCandidateId":"${auditorB.block.targetCandidateId}"}]
Round 1: assign ${coordinator.block.agentId} to role ${coordinator.block.role.id}. It maps all 33 requirement IDs to
assignment-scoped observations, checks, timeline caveats, and evidence gaps without proposing final answers.
Round 2: after coordination completes, assign ${windows.block.agentId}, ${native.block.agentId}, ${managed.block.agentId}, and
${batch.block.agentId} together to roles ${windows.block.role.id}, ${native.block.role.id}, ${managed.block.role.id}, and
${batch.block.role.id}. Give every specialist the coordinator report, but keep each within its declared assignments.
Round 3: after all four specialist reports complete, assign ${solverA.block.agentId} and ${solverB.block.agentId} together to role
${solverA.block.role.id}. Give both the coordinator and specialist reports. The solvers remain independent,
re-read the immutable evidence, falsify leads, answer every requirement, and each writes only result.json
and report.md. They must distinguish upstream \`evidence_checks_relied_on\` provenance from
trace-visible candidate \`checks_performed\`.
Round 4: after both candidate snapshots and evaluator outputs exist, assign ${auditorA.block.agentId} to
${auditorA.block.targetCandidateId} and ${auditorB.block.agentId} to ${auditorB.block.targetCandidateId} using role
${auditorA.block.role.id} and the exact corresponding targetCandidateId. Auditors rerun the evaluator and
audit evidence alignment and trace integrity without selecting.
Round 5: accept the highest-scoring evaluator-passing candidate whose pinned assurance audit passes.
Break an exact score tie by candidate ordinal (${solverA.block.agentId} before ${solverB.block.agentId}). If neither
qualifies, stop. Never execute specimen content, use network, inspect host paths, expose credentials,
skip a phase, dispatch an undeclared member, change scope, or ask for more turns.`,
    },
    roles: rolesForSecurityTeamPlan(COURSE_SECURITY_EVALUATION_TEAM_PLAN).map((role) => ({
      ...role,
      model,
    })),
    limits: COURSE_SECURITY_EVALUATION_WORKFLOW_LIMITS,
    evaluation: {
      command: ["node", exercise.evaluatorPath],
      timeoutSeconds: 30,
    },
    codex: {
      binary: "codex",
      ignoreUserConfig: true,
      maxOutputBytes: 12 * 1024 * 1024,
    },
  };
}

export function sourceSecurityAuditWorkflow(
  audit: SourceSecurityAuditWorkspace,
): WorkflowDefinition {
  const recon = securityRoleAssignment(SOURCE_SECURITY_AUDIT_TEAM_PLAN, "source_recon");
  const injection = securityRoleAssignment(
    SOURCE_SECURITY_AUDIT_TEAM_PLAN,
    "source_injection_hunt",
  );
  const boundary = securityRoleAssignment(SOURCE_SECURITY_AUDIT_TEAM_PLAN, "source_boundary_hunt");
  const authorization = securityRoleAssignment(
    SOURCE_SECURITY_AUDIT_TEAM_PLAN,
    "source_authorization_hunt",
  );
  const falsifierA = securityRoleAssignment(
    SOURCE_SECURITY_AUDIT_TEAM_PLAN,
    "source_falsification_a",
  );
  const falsifierB = securityRoleAssignment(
    SOURCE_SECURITY_AUDIT_TEAM_PLAN,
    "source_falsification_b",
  );
  const auditorA = securityRoleAssignment(
    SOURCE_SECURITY_AUDIT_TEAM_PLAN,
    "source_evaluation_audit_a",
  );
  const auditorB = securityRoleAssignment(
    SOURCE_SECURITY_AUDIT_TEAM_PLAN,
    "source_evaluation_audit_b",
  );
  return {
    version: 1,
    name: "source_security_audit",
    objective:
      "Produce a complete attacker-oriented static source audit whose findings survive independent adversarial falsification.",
    configPath: `${audit.root}/workflow.json`,
    workspace: audit.root,
    allowDirtyWorkspace: false,
    supervisor: {
      model: undefined,
      instructions: `Use this exact bounded sequence and no other sequence:
Round 1: assign ${recon.block.agentId} to role ${recon.block.role.id}. It inventories production entry points, inputs,
trust boundaries, shared security controls, and call relationships across all in-scope files.
Round 2: after recon completes, assign ${injection.block.agentId}, ${boundary.block.agentId}, and ${authorization.block.agentId} together
to ${injection.block.role.id}, ${boundary.block.role.id}, and ${authorization.block.role.id} respectively. Include the recon report
in every task. Each hunter follows attacker-controlled flows forward, proposes candidates, evaluates
all five finding gates, and records leads that fail a gate.
Round 3: after all hunt reports complete, assign ${falsifierA.block.agentId} and ${falsifierB.block.agentId} together to role
${falsifierA.block.role.id}. Include recon and all three hunt reports in both tasks. Each candidate independently
tries to disprove every lead, completes the surface inventory, and writes only result.json and
report.md.
Round 4: after both candidate snapshots and evaluator outputs exist, assign ${auditorA.block.agentId} to ${auditorA.block.targetCandidateId}
and ${auditorB.block.agentId} to ${auditorB.block.targetCandidateId} using role ${auditorA.block.role.id} and the corresponding targetCandidateId.
Round 5: accept the highest-scoring evaluator-passing candidate whose pinned audit passes. Break an
exact score tie by candidate ordinal (${falsifierA.block.agentId} before ${falsifierB.block.agentId}). If neither qualifies, stop.
Never execute target code, install dependencies, use network, skip a phase, dispatch an undeclared
agent, change scope, or ask for more turns.`,
    },
    roles: rolesForSecurityTeamPlan(SOURCE_SECURITY_AUDIT_TEAM_PLAN),
    limits: SOURCE_SECURITY_AUDIT_WORKFLOW_LIMITS,
    evaluation: {
      command: ["node", audit.evaluatorPath],
      timeoutSeconds: 30,
    },
    codex: {
      binary: "codex",
      ignoreUserConfig: true,
      maxOutputBytes: 8 * 1024 * 1024,
    },
  };
}

export function sourceSecurityFixWorkflow(fix: SourceSecurityFixWorkspace): WorkflowDefinition {
  const planner = securityRoleAssignment(SOURCE_SECURITY_FIX_TEAM_PLAN, "source_fix_plan");
  const engineerA = securityRoleAssignment(SOURCE_SECURITY_FIX_TEAM_PLAN, "source_fix_a");
  const engineerB = securityRoleAssignment(SOURCE_SECURITY_FIX_TEAM_PLAN, "source_fix_b");
  const auditorA = securityRoleAssignment(SOURCE_SECURITY_FIX_TEAM_PLAN, "source_fix_audit_a");
  const auditorB = securityRoleAssignment(SOURCE_SECURITY_FIX_TEAM_PLAN, "source_fix_audit_b");
  return {
    version: 1,
    name: "source_security_fix",
    objective:
      "Produce a focused source patch and regression tests that address every accepted static-audit finding without executing project code.",
    configPath: `${fix.root}/workflow.json`,
    workspace: fix.root,
    allowDirtyWorkspace: false,
    supervisor: {
      model: undefined,
      instructions: `Use this exact bounded sequence and no other sequence:
Round 1: assign ${planner.block.agentId} to role ${planner.block.role.id}. It re-reads every accepted finding and relevant
source, identifies root causes and equivalent variants, and maps each finding to implementation and
regression-test changes. It does not edit.
Round 2: after planning completes, assign ${engineerA.block.agentId} and ${engineerB.block.agentId} together to role ${engineerA.block.role.id}.
Include the complete planner report in both tasks. Each candidate independently edits only target/
and writes result.json and report.md.
Round 3: after both candidate snapshots and evaluator outputs exist, assign ${auditorA.block.agentId} to ${auditorA.block.targetCandidateId}
and ${auditorB.block.agentId} to ${auditorB.block.targetCandidateId} using role ${auditorA.block.role.id} and the corresponding targetCandidateId.
Round 4: accept the highest-scoring evaluator-passing candidate whose pinned audit passes. Break an
exact score tie by candidate ordinal (${engineerA.block.agentId} before ${engineerB.block.agentId}). If neither qualifies, stop.
Never execute target code or project scripts, install dependencies, use network, skip a phase,
dispatch an undeclared agent, claim Drone validation, change scope, or ask for more turns.`,
    },
    roles: rolesForSecurityTeamPlan(SOURCE_SECURITY_FIX_TEAM_PLAN),
    limits: SOURCE_SECURITY_FIX_WORKFLOW_LIMITS,
    evaluation: {
      command: ["node", fix.evaluatorPath],
      timeoutSeconds: 30,
    },
    codex: {
      binary: "codex",
      ignoreUserConfig: true,
      maxOutputBytes: 8 * 1024 * 1024,
    },
  };
}
