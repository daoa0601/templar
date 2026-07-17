import type { WorkflowDefinition } from "aiur-orchestrator";

import type { TelecomIncidentWorkspace } from "./workspace.js";

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
