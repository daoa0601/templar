import type { WorkflowDefinition } from "aiur-orchestrator";

import type {
  ExerciseSolveWorkspace,
  PcapSecurityTriageWorkspace,
  TelecomIncidentWorkspace,
} from "./workspace.js";

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
Round 1: assign research_once to role security_evidence_researcher. It identifies the most relevant
packet observations, uncertainty, plausible alternatives, and applicable playbook principles only.
Round 2: after research completes, assign candidate_a and candidate_b together to role
security_analyst. Include the researcher's relevant observation IDs and gaps in both tasks. The two
analysts remain independent and each writes only result.json and report.md.
Round 3: accept the highest scoring evaluator-passing candidate. Break an exact score tie by
candidate ordinal (candidate_a before candidate_b). If neither passes, stop. Never add a reviewer
round, skip the research phase, dispatch an undeclared agent, change scope, or ask for more turns.`,
    },
    roles: [
      {
        id: "security_evidence_researcher",
        kind: "research",
        description: "Read-only prioritization of packet facts, alternatives, and missing context.",
        instructions:
          "Read evidence.json, triage-playbook.json, and evaluation/context.json. Identify important observation IDs, plausible benign alternatives, and missing endpoint, identity, asset, baseline, and capture context. Do not edit, use network, claim compromise, or spawn agents.",
        maxInstances: 1,
        maxTurns: 1,
        model: undefined,
      },
      {
        id: "security_analyst",
        kind: "candidate",
        description: "Independent passive PCAP security triage analyst.",
        instructions:
          "Follow CANDIDATE_INSTRUCTIONS.md. Write result.json and report.md only. Ground hypotheses in known observation and principle IDs, name alternatives and unknowns, choose only declared passive actions, and never use network or mutate external systems.",
        maxInstances: 2,
        maxTurns: 1,
        model: undefined,
      },
    ],
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
