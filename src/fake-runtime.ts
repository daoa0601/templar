import { execFile } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { RuntimeError } from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import type {
  AgentRuntime,
  RuntimeTurnInput,
  RuntimeTurnResult,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import { Effect } from "effect";

const execFileAsync = promisify(execFile);

interface FakeEvaluationContext {
  readonly expected_severity: string;
  readonly boundary_ambiguous: boolean;
  readonly known_evidence_ids: ReadonlyArray<string>;
  readonly known_citations: ReadonlyArray<{
    readonly document_id: string;
    readonly section_id: string;
  }>;
  readonly known_metrics: ReadonlyArray<{
    readonly fact_id: string;
    readonly metric: string;
    readonly value: number;
  }>;
  readonly required_action_ids: ReadonlyArray<string>;
  readonly required_unknown_ids: ReadonlyArray<string>;
  readonly allowed_actions: ReadonlyArray<{
    readonly action_id: string;
    readonly ordinal: number;
    readonly rule_id: string;
    readonly prerequisites: ReadonlyArray<string>;
  }>;
  readonly available_checks: ReadonlyArray<string>;
}

interface FakePcapSecurityContext {
  readonly required_observation_ids: ReadonlyArray<string>;
  readonly known_principle_ids: ReadonlyArray<string>;
  readonly required_unknown_ids: ReadonlyArray<string>;
  readonly allowed_actions: ReadonlyArray<{
    readonly action_id: string;
    readonly ordinal: number;
  }>;
  readonly available_checks: ReadonlyArray<string>;
}

interface FakeExerciseContext {
  readonly required_question_ids: ReadonlyArray<string>;
  readonly required_observation_ids: ReadonlyArray<string>;
  readonly known_observation_ids: ReadonlyArray<string>;
  readonly available_evidence_checks: ReadonlyArray<string>;
  readonly candidate_checks_available: ReadonlyArray<string>;
  readonly question_observation_namespaces?: ReadonlyArray<{
    readonly question_id: string;
    readonly observation_prefix: string;
  }>;
}

interface FakeSourceSurface {
  readonly files: ReadonlyArray<{ readonly path: string; readonly in_scope: boolean }>;
  readonly entry_points: ReadonlyArray<{
    readonly hint_id: string;
    readonly path: string;
    readonly line: number;
  }>;
  readonly input_hints: ReadonlyArray<{
    readonly hint_id: string;
    readonly path: string;
    readonly line: number;
  }>;
  readonly sink_hints: ReadonlyArray<{
    readonly hint_id: string;
    readonly path: string;
    readonly line: number;
  }>;
  readonly available_checks: ReadonlyArray<string>;
}

interface FakeSourceFixContext {
  readonly findings: ReadonlyArray<{
    readonly finding_id: string;
    readonly primary_location: { readonly path: string; readonly line: number };
    readonly data_flow: ReadonlyArray<{ readonly path: string; readonly line: number }>;
  }>;
  readonly required_promotion_impact: "high" | "routine";
}

const agentReport = JSON.stringify({
  status: "completed",
  summary: "Completed the assigned bounded phase.",
  evidence: ["Used only the immutable local case workspace."],
  risks: [],
  nextSteps: [],
});

function result(threadId: string, finalText: string): RuntimeTurnResult {
  return {
    threadId,
    finalText,
    usage: { inputTokens: 20, cachedInputTokens: 0, outputTokens: 20, totalTokens: 40 },
    events: [{ type: "templar.fake.turn" }],
  };
}

async function writeCandidate(input: RuntimeTurnInput, completeCoverage: boolean): Promise<void> {
  const context = JSON.parse(
    await readFile(path.join(input.cwd, "evaluation", "context.json"), "utf8"),
  ) as FakeEvaluationContext;
  const actions = context.allowed_actions
    .filter((action) => context.required_action_ids.includes(action.action_id))
    .filter((_action, index, all) => completeCoverage || index < all.length - 1)
    .map((action) => ({
      ordinal: action.ordinal,
      action_id: action.action_id,
      source_rule_ids: [action.rule_id],
      prerequisites: action.prerequisites,
    }));
  const evidenceIds = completeCoverage
    ? context.known_evidence_ids
    : context.known_evidence_ids.slice(0, Math.max(1, context.known_evidence_ids.length - 1));
  const unknownIds = completeCoverage
    ? context.required_unknown_ids
    : context.required_unknown_ids.slice(0, Math.max(0, context.required_unknown_ids.length - 1));
  const citations = context.known_citations.filter(
    (citation) =>
      citation.document_id === "SOP-NET-001" &&
      ["SOP-NET-001#1", "SOP-NET-001#2.1", "SOP-NET-001#2.2", "SOP-NET-001#3"].includes(
        citation.section_id,
      ),
  );
  const hasPolicyFinding = context.known_metrics.length > 0;
  const output = {
    schema_version: "1",
    status: context.boundary_ambiguous ? "needs_review" : "completed",
    summary: hasPolicyFinding
      ? `Packet evidence maps to ${context.expected_severity}; unresolved device checks remain.`
      : "The incident needs the declared local device checks; no packet metric was supplied.",
    severity: context.expected_severity,
    evidence_ids: evidenceIds,
    citations,
    metric_claims: context.known_metrics,
    findings: hasPolicyFinding
      ? [
          {
            finding_id: "finding.tcp_retransmission_policy",
            rule_id: "POLICY-TCP-RETRANS-001",
            severity: context.expected_severity,
            evidence_ids: ["evidence.pcap.capture"],
            statement: "The persisted retransmission metric was classified by the active policy.",
          },
        ]
      : [],
    action_plan: actions,
    unknown_ids: unknownIds,
    checks_performed: context.available_checks,
    evaluationAudit: {
      checks_rerun: ["deterministic_evaluator"],
      suspicious_behavior: [],
      findings: [],
      disposition: "pass",
      manualAuditRequired: false,
      trace_available: false,
    },
    promotion: {
      impact: context.expected_severity === "high" ? "high" : "routine",
      security_outcome: false,
      headline_result: false,
    },
    external_mutations: [],
  };
  await writeFile(
    path.join(input.cwd, "result.json"),
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    path.join(input.cwd, "report.md"),
    `# Network incident report\n\n${output.summary}\n\nEvidence and policy identifiers are recorded in result.json. No external mutation was performed.\n\n## Audit findings\n\nThe deterministic local evaluator was rerun; no suspicious candidate behavior was observed during the candidate self-check.\n`,
    "utf8",
  );
  for (let iteration = 0; iteration < 2; iteration += 1) {
    await execFileAsync("node", [path.join(input.cwd, "evaluation", "evaluate.mjs")], {
      cwd: input.cwd,
      encoding: "utf8",
      timeout: 10_000,
    }).catch(() => undefined);
  }
}

async function writeSecurityCandidate(
  input: RuntimeTurnInput,
  completeCoverage: boolean,
): Promise<void> {
  const context = JSON.parse(
    await readFile(path.join(input.cwd, "evaluation", "context.json"), "utf8"),
  ) as FakePcapSecurityContext;
  const observationIds = completeCoverage
    ? context.required_observation_ids
    : context.required_observation_ids.slice(
        0,
        Math.max(1, context.required_observation_ids.length - 1),
      );
  const unknownIds = completeCoverage
    ? context.required_unknown_ids
    : context.required_unknown_ids.slice(0, Math.max(1, context.required_unknown_ids.length - 1));
  const actionIds = context.allowed_actions
    .filter((_action, index, all) => completeCoverage || index < all.length - 1)
    .map((action) => action.action_id);
  const output = {
    schema_version: "1",
    status: "needs_review",
    summary:
      "The packet observations warrant passive review; endpoint, identity, asset, and baseline context remain unavailable.",
    assessment: "suspicious_needs_review",
    observation_ids: observationIds,
    hypotheses: [
      {
        hypothesis_id: "hypothesis.automated_or_unexpected_network_activity",
        statement:
          "The observed traffic pattern may represent automated or unexpected activity that needs host and network correlation.",
        confidence: "low",
        observation_ids: observationIds.slice(0, Math.min(3, observationIds.length)),
        principle_ids: context.known_principle_ids.slice(0, 3),
        alternatives: ["approved remote administration", "monitoring or update traffic"],
        unknown_ids: unknownIds,
        kill_chain_stage: null,
      },
    ],
    unknown_ids: unknownIds,
    advisory_action_ids: actionIds,
    checks_performed: context.available_checks,
    promotion: {
      impact: "routine",
      security_outcome: true,
      headline_result: false,
    },
    external_mutations: [],
  };
  await writeFile(
    path.join(input.cwd, "result.json"),
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    path.join(input.cwd, "report.md"),
    `# Observed facts\n\nThe bounded observation IDs are listed in result.json.\n\n# Hypotheses\n\nThe traffic may be automated or unexpected; approved administration and routine service activity remain plausible alternatives.\n\n# Defensive next steps\n\nPreserve the capture and correlate it with authorized asset, endpoint, identity, and baseline evidence. No external mutation was performed.\n`,
    "utf8",
  );
}

async function writeExerciseCandidate(
  input: RuntimeTurnInput,
  completeCoverage: boolean,
): Promise<void> {
  const context = JSON.parse(
    await readFile(path.join(input.cwd, "evaluation", "context.json"), "utf8"),
  ) as FakeExerciseContext;
  const completeObservations =
    context.required_observation_ids.length > 0
      ? context.required_observation_ids
      : context.known_observation_ids;
  const limitedObservations = context.known_observation_ids.slice(0, 1);
  const namespaces = new Map(
    (context.question_observation_namespaces ?? []).map((entry) => [
      entry.question_id,
      entry.observation_prefix,
    ]),
  );
  const output = {
    schema_version: "1",
    status: "completed",
    summary: "Every bounded exercise question was answered from the supplied static observations.",
    answers: context.required_question_ids.map((questionId, index) => ({
      question_id: questionId,
      answer: `The scripted runtime produced a structurally grounded answer for ${questionId}.`,
      observation_ids: (() => {
        const namespace = namespaces.get(questionId);
        if (namespace !== undefined) {
          const scoped = completeObservations.filter((observationId) =>
            observationId.startsWith(namespace),
          );
          const scopedQuestions = context.required_question_ids.filter(
            (candidateQuestionId) => namespaces.get(candidateQuestionId) === namespace,
          );
          const scopedQuestionIndex = scopedQuestions.indexOf(questionId);
          if (scoped.length === 0 || scopedQuestionIndex < 0 || scopedQuestions.length === 0) {
            throw new Error(`The scripted runtime has no scoped observation for ${questionId}.`);
          }
          const assigned = scoped.filter(
            (_, observationIndex) =>
              observationIndex % scopedQuestions.length === scopedQuestionIndex,
          );
          return assigned.length > 0 ? assigned : [scoped[scopedQuestionIndex % scoped.length]!];
        }
        return completeCoverage
          ? [completeObservations[index % completeObservations.length]!]
          : limitedObservations;
      })(),
      uncertainty:
        "Semantic correctness is outside the scripted runtime; use the course smoke grade.",
    })),
    unanswered_question_ids: [],
    evidence_checks_relied_on: context.available_evidence_checks,
    checks_performed: context.candidate_checks_available,
    external_mutations: [],
  };
  await writeFile(
    path.join(input.cwd, "result.json"),
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    path.join(input.cwd, "report.md"),
    `# Answers\n\nAll required question IDs have structured answers in result.json.\n\n# Method\n\nUsed only the bounded analyzer observations supplied in the immutable exercise snapshot.\n\n# Uncertainty\n\nThe scripted runtime validates orchestration and contracts, not semantic course correctness.\n`,
    "utf8",
  );
}

async function writeSourceCandidate(
  input: RuntimeTurnInput,
  completeCoverage: boolean,
): Promise<void> {
  const surface = JSON.parse(
    await readFile(path.join(input.cwd, "source-surface.json"), "utf8"),
  ) as FakeSourceSurface;
  const maybeLimited = <Value>(values: ReadonlyArray<Value>): ReadonlyArray<Value> =>
    completeCoverage ? values : values.slice(0, Math.max(0, values.length - 1));
  const entry = surface.entry_points[0];
  const sourceInput = surface.input_hints.find((hint) => hint.path === entry?.path);
  const sink = surface.sink_hints.find((hint) => hint.path === entry?.path);
  const confirmedFinding =
    completeCoverage && entry !== undefined && sourceInput !== undefined && sink !== undefined
      ? [
          {
            finding_id: "FINDING-001",
            title: "Attacker-controlled input reaches a sensitive source boundary",
            cwe: "CWE-22",
            severity: "high",
            confidence: "medium",
            primary_location: { path: sink.path, line: sink.line },
            entry_point_hint_ids: [entry.hint_id],
            input_hint_ids: [sourceInput.hint_id],
            sink_hint_ids: [sink.hint_id],
            data_flow: [
              {
                path: sourceInput.path,
                line: sourceInput.line,
                description: "The production entry reads attacker-controlled request data.",
              },
              {
                path: sink.path,
                line: sink.line,
                description:
                  "The value reaches the indexed sensitive operation without a visible boundary check.",
              },
            ],
            gates: Object.fromEntries(
              [
                "unintended_behavior",
                "production_reachability",
                "attacker_control",
                "defense_failure",
                "new_capability",
              ].map((name) => [
                name,
                {
                  passed: true,
                  evidence: `The bounded scripted fixture supplies evidence for ${name}.`,
                },
              ]),
            ),
            attack: "Supply boundary-breaking input through the indexed production entry point.",
            impact: "The sensitive operation may expose data outside its intended boundary.",
            fix_strategy:
              "Canonicalize against a fixed root, reject boundary escapes, and add a regression test.",
          },
        ]
      : [];
  const output = {
    schema_version: "1",
    status: "completed",
    summary: completeCoverage
      ? "The scripted audit completed the static production surface inventory and retained one bounded fixture finding."
      : "The scripted audit intentionally left surface coverage incomplete.",
    coverage: {
      scanned_file_paths: maybeLimited(
        surface.files.filter((file) => file.in_scope).map((file) => file.path),
      ),
      entry_point_dispositions: maybeLimited(surface.entry_points).map((hint) => ({
        hint_id: hint.hint_id,
        disposition: "analyzed",
        rationale: "The scripted runtime recorded this lexical lead for orchestration coverage.",
      })),
      input_dispositions: maybeLimited(surface.input_hints).map((hint) => ({
        hint_id: hint.hint_id,
        disposition:
          confirmedFinding.length > 0 && hint.hint_id === sourceInput?.hint_id
            ? "attacker_controlled"
            : "not_attacker_controlled",
        rationale:
          confirmedFinding.length > 0 && hint.hint_id === sourceInput?.hint_id
            ? "The bounded fixture explicitly reads this value from the request."
            : "The scripted runtime makes no semantic attacker-control claim for this lead.",
      })),
      sink_dispositions: maybeLimited(surface.sink_hints).map((hint) => ({
        hint_id: hint.hint_id,
        disposition:
          confirmedFinding.length > 0 && hint.hint_id === sink?.hint_id
            ? "reachable"
            : "not_security_relevant",
        rationale:
          confirmedFinding.length > 0 && hint.hint_id === sink?.hint_id
            ? "The bounded fixture places this operation in the indexed route."
            : "The scripted runtime makes no semantic reachability claim for this lead.",
      })),
    },
    findings: confirmedFinding,
    eliminated_candidates: [],
    checks_performed: surface.available_checks,
    promotion: {
      impact: confirmedFinding.length === 0 ? "routine" : "high",
      security_outcome: true,
      headline_result: false,
    },
    external_mutations: [],
  };
  await writeFile(
    path.join(input.cwd, "result.json"),
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    path.join(input.cwd, "report.md"),
    `# Scope\n\nBounded production source snapshot.\n\n# Attack surface\n\nThe lexical inventory is dispositioned in result.json.\n\n# Confirmed findings\n\n${confirmedFinding.length === 0 ? "No complete finding is asserted." : "One bounded fixture finding is recorded in result.json."}\n\n# Eliminated candidates\n\nNone were generated by the scripted runtime.\n\n# Limitations\n\nThis runtime validates orchestration and deterministic contracts, not general source semantics.\n`,
    "utf8",
  );
}

async function writeSourceFixCandidate(
  input: RuntimeTurnInput,
  completeCoverage: boolean,
): Promise<void> {
  const context = JSON.parse(
    await readFile(path.join(input.cwd, "source-fix-context.json"), "utf8"),
  ) as FakeSourceFixContext;
  const findings = completeCoverage ? context.findings : context.findings.slice(0, -1);
  const findingsByPath = new Map<string, Array<string>>();
  for (const finding of context.findings) {
    const current = findingsByPath.get(finding.primary_location.path) ?? [];
    current.push(finding.finding_id);
    findingsByPath.set(finding.primary_location.path, current);
  }
  const changes: Array<Record<string, unknown>> = [];
  for (const [sourcePath, findingIds] of findingsByPath) {
    const destination = path.join(input.cwd, "target", ...sourcePath.split("/"));
    const original = await readFile(destination, "utf8");
    await writeFile(
      destination,
      `${original.replace(/\s*$/u, "")}\n\n// Security boundary hardened for ${findingIds.join(", ")}.\n`,
      "utf8",
    );
    changes.push({
      path: sourcePath,
      status: "modified",
      finding_ids: findingIds,
      rationale: "Harden the shared sensitive boundary identified by the accepted audit.",
    });
  }

  const testPath = "tests/templar-source-security-fix.test.ts";
  if (completeCoverage) {
    const destination = path.join(input.cwd, "target", ...testPath.split("/"));
    await mkdir(path.dirname(destination), { recursive: true });
    const alreadyExists = await access(destination).then(
      () => true,
      () => false,
    );
    const previous = alreadyExists ? await readFile(destination, "utf8") : "";
    await writeFile(
      destination,
      `${previous}${previous.length === 0 ? "" : "\n"}test("rejects boundary-breaking security input", () => {\n  // The real candidate supplies a project-specific regression at this boundary.\n});\n`,
      "utf8",
    );
    changes.push({
      path: testPath,
      status: alreadyExists ? "modified" : "added",
      finding_ids: context.findings.map((finding) => finding.finding_id),
      rationale: "Cover every accepted finding with a focused boundary regression.",
    });
  }

  const output = {
    schema_version: "1",
    status: "completed",
    summary: completeCoverage
      ? "Every accepted fixture finding has a scoped source change and regression test."
      : "This candidate intentionally leaves accepted findings unresolved.",
    finding_resolutions: findings.map((finding) => ({
      finding_id: finding.finding_id,
      root_cause:
        "Attacker-controlled data reached a sensitive boundary without a fixed-root check.",
      changed_paths: [finding.primary_location.path],
      regression_test_paths: completeCoverage ? [testPath] : [],
      variant_locations: [
        finding.primary_location,
        ...finding.data_flow
          .filter(
            (location, index, all) =>
              all.findIndex(
                (candidate) => candidate.path === location.path && candidate.line === location.line,
              ) === index &&
              (location.path !== finding.primary_location.path ||
                location.line !== finding.primary_location.line),
          )
          .map((location) => ({ path: location.path, line: location.line })),
      ],
      residual_risk:
        "Project-specific dynamic behavior remains untested until an approved Drone replay.",
    })),
    changes,
    tests: completeCoverage
      ? [
          {
            path: testPath,
            finding_ids: context.findings.map((finding) => finding.finding_id),
            expected_behavior:
              "Boundary-breaking input is rejected before the sensitive operation.",
          },
        ]
      : [],
    dynamic_validation: { status: "not_run", job_id: null },
    promotion: {
      impact: context.required_promotion_impact,
      security_outcome: true,
      headline_result: false,
    },
    external_mutations: [],
  };
  await writeFile(
    path.join(input.cwd, "result.json"),
    `${JSON.stringify(output, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    path.join(input.cwd, "report.md"),
    `# Fix summary\n\nScoped source boundary changes are listed in result.json.\n\n# Finding coverage\n\n${completeCoverage ? "Every accepted finding has an implementation change." : "This candidate is intentionally incomplete."}\n\n# Tests\n\n${completeCoverage ? "Focused regression tests were added but not executed." : "No complete regression coverage was supplied."}\n\n# Residual risk\n\nDynamic validation was not run; any replay requires a separately approved Drone operation.\n`,
    "utf8",
  );
}

async function workflowId(cwd: string): Promise<string> {
  const parsed = JSON.parse(await readFile(path.join(cwd, "workflow.json"), "utf8")) as unknown;
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    !("workflow_id" in parsed) ||
    typeof parsed.workflow_id !== "string"
  ) {
    throw new Error("Fake runtime could not resolve the workflow ID.");
  }
  return parsed.workflow_id;
}

async function auditCandidate(input: RuntimeTurnInput): Promise<string> {
  const tracePath = path.join(input.cwd, ".harness-audit", "trace.jsonl");
  const traceAvailable = await access(tracePath).then(
    () => true,
    () => false,
  );
  let traceInspected = false;
  let traceComplete = false;
  if (traceAvailable) {
    try {
      const firstLine = (await readFile(tracePath, "utf8")).split("\n", 1)[0];
      const header = JSON.parse(firstLine ?? "null") as unknown;
      if (
        typeof header === "object" &&
        header !== null &&
        !Array.isArray(header) &&
        "type" in header &&
        header.type === "trace.header"
      ) {
        traceInspected = true;
        traceComplete = "truncated" in header && header.truncated === false;
      }
    } catch {
      traceInspected = false;
    }
  }
  const evaluation = await execFileAsync(
    "node",
    [path.join(input.cwd, "evaluation", "evaluate.mjs")],
    {
      cwd: input.cwd,
      encoding: "utf8",
      timeout: 10_000,
    },
  ).then(
    (run) => run.stdout.trim(),
    (error: unknown) =>
      typeof error === "object" && error !== null && "stdout" in error
        ? String(error.stdout).trim()
        : "evaluator failed",
  );
  let evaluatorPassed = false;
  try {
    const parsed = JSON.parse(evaluation) as unknown;
    evaluatorPassed =
      typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed) &&
      "passed" in parsed &&
      parsed.passed === true;
  } catch {
    evaluatorPassed = false;
  }
  const manualReview = !traceComplete || !evaluatorPassed;
  const traceFinding = !traceAvailable
    ? "candidate trace unavailable; degraded audit"
    : !traceInspected
      ? "candidate trace header malformed; degraded audit"
      : !traceComplete
        ? "candidate trace truncated; degraded audit"
        : "complete candidate trace inspected; no suspicious behavior found";
  return JSON.stringify({
    status: "completed",
    summary: manualReview
      ? "Reran the deterministic evaluator; trace or evaluator coverage requires manual review."
      : "Reran the deterministic evaluator and inspected the complete scoped trace; no gaming indicators were observed.",
    evidence: [
      "audit.checks_rerun=deterministic_evaluator,evaluator_contract,git_diff",
      "audit.suspicious_behavior=none",
      `audit.finding=${traceFinding}`,
      `audit.disposition=${manualReview ? "manual_review" : "pass"}`,
      `audit.manualAuditRequired=${manualReview ? "true" : "false"}`,
      `audit.trace_inspected=${traceInspected ? "true" : "false"}`,
      `audit.trace_complete=${traceComplete ? "true" : "false"}`,
      `audit.evaluator_output=${evaluation.slice(0, 1000)}`,
    ],
    risks: manualReview ? ["Evaluation-audit coverage is degraded and requires human review."] : [],
    nextSteps: manualReview ? ["Perform a complete manual trace audit before promotion."] : [],
  });
}

export class ScriptedTemplarRuntime implements AgentRuntime {
  #supervisorTurns = 0;

  readonly metadata = {
    adapter: "templar-scripted",
    binary: null,
    ignoreUserConfig: true,
    maxOutputBytes: null,
    toolPolicy: "scripted-no-model",
  } as const;

  readonly runTurn = (input: RuntimeTurnInput) =>
    Effect.tryPromise({
      try: async () => {
        const workflow = await workflowId(input.cwd);
        if (input.agentId !== "supervisor") {
          if (input.agentId === "candidate_a") {
            if (workflow === "pcap_security_triage") await writeSecurityCandidate(input, true);
            else if (workflow === "exercise_solve" || workflow === "course_security_evaluation")
              await writeExerciseCandidate(input, true);
            else if (workflow === "source_security_audit") await writeSourceCandidate(input, true);
            else if (workflow === "source_security_fix") await writeSourceFixCandidate(input, true);
            else await writeCandidate(input, true);
          }
          if (input.agentId === "candidate_b") {
            if (workflow === "pcap_security_triage") await writeSecurityCandidate(input, false);
            else if (workflow === "exercise_solve" || workflow === "course_security_evaluation")
              await writeExerciseCandidate(input, false);
            else if (workflow === "source_security_audit") await writeSourceCandidate(input, false);
            else if (workflow === "source_security_fix")
              await writeSourceFixCandidate(input, false);
            else await writeCandidate(input, false);
          }
          const finalText = input.agentId.startsWith("audit_")
            ? await auditCandidate(input)
            : agentReport;
          return result(`${input.agentId}-thread`, finalText);
        }

        this.#supervisorTurns += 1;
        if (workflow === "course_security_evaluation") {
          if (this.#supervisorTurns === 1) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Map the complete course corpus, evidence namespaces, and gaps.",
                assignments: [
                  {
                    agentId: "course_recon_once",
                    roleId: "course_evidence_coordinator",
                    task: "Map every requirement to bounded observations and explicit gaps.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 2) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Dispatch the four assignment-scoped passive specialist blocks.",
                assignments: [
                  {
                    agentId: "windows_intrusion_once",
                    roleId: "course_windows_intrusion_specialist",
                    task: "Correlate the Windows forensic facts and timeline without overclaiming.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "native_re_once",
                    roleId: "course_native_re_specialist",
                    task: "Recover native static and anti-analysis semantics passively.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "managed_re_once",
                    roleId: "course_managed_re_specialist",
                    task: "Reproduce managed packing, metadata, resources, and crypto.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "batch_re_once",
                    roleId: "course_batch_re_specialist",
                    task: "Review bounded all-sample automation and completeness.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 3) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Create two independent whole-corpus solutions.",
                assignments: [
                  {
                    agentId: "candidate_a",
                    roleId: "course_whole_corpus_solver",
                    task: "Solve all requirements and falsify specialist leads from the evidence.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "candidate_b",
                    roleId: "course_whole_corpus_solver",
                    task: "Independently solve all requirements and preserve uncertainty.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 4) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Audit both pinned whole-corpus candidates.",
                assignments: [
                  {
                    agentId: "audit_a",
                    roleId: "evaluation_auditor",
                    task: "Audit candidate_a evidence alignment, evaluator output, diff, and trace.",
                    targetCandidateId: "candidate_a",
                  },
                  {
                    agentId: "audit_b",
                    roleId: "evaluation_auditor",
                    task: "Audit candidate_b evidence alignment, evaluator output, diff, and trace.",
                    targetCandidateId: "candidate_b",
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "accept",
              summary: "Accept the highest-scoring evaluator-passing, assurance-cleared solution.",
              assignments: [],
              selectedCandidateId: "candidate_a",
            }),
          );
        }
        if (workflow === "source_security_fix") {
          if (this.#supervisorTurns === 1) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary:
                  "Plan root-cause fixes and regression coverage for every accepted finding.",
                assignments: [
                  {
                    agentId: "plan_once",
                    roleId: "fix_planner",
                    task: "Map every accepted finding to its root cause, variants, patch, and regression test.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 2) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Create two independent isolated source-fix candidates.",
                assignments: [
                  {
                    agentId: "candidate_a",
                    roleId: "fix_candidate",
                    task: "Implement every accepted fix and add focused unexecuted regressions.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "candidate_b",
                    roleId: "fix_candidate",
                    task: "Independently implement the accepted fixes and regression coverage.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 3) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Audit both pinned source-fix candidates.",
                assignments: [
                  {
                    agentId: "audit_a",
                    roleId: "evaluation_auditor",
                    task: "Audit candidate_a patch, finding coverage, tests, evaluator, and trace.",
                    targetCandidateId: "candidate_a",
                  },
                  {
                    agentId: "audit_b",
                    roleId: "evaluation_auditor",
                    task: "Audit candidate_b patch, finding coverage, tests, evaluator, and trace.",
                    targetCandidateId: "candidate_b",
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "accept",
              summary: "Accept the highest-scoring evaluator-passing, audit-cleared patch.",
              assignments: [],
              selectedCandidateId: "candidate_b",
            }),
          );
        }
        if (workflow === "source_security_audit") {
          if (this.#supervisorTurns === 1) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Inventory the complete production source attack surface.",
                assignments: [
                  {
                    agentId: "recon_once",
                    roleId: "source_recon",
                    task: "Map production entry points, inputs, shared controls, and call relationships.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 2) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Run three independently scoped source hunts.",
                assignments: [
                  {
                    agentId: "injection_once",
                    roleId: "injection_hunter",
                    task: "Trace attacker inputs into interpreter and injection boundaries.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "boundary_once",
                    roleId: "boundary_hunter",
                    task: "Trace file, URL, navigation, request, and deserialization boundaries.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "authorization_once",
                    roleId: "authorization_hunter",
                    task: "Inspect authorization, state, race, secret, and resource-abuse paths.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 3) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Independently falsify all source-audit leads.",
                assignments: [
                  {
                    agentId: "candidate_a",
                    roleId: "source_falsifier",
                    task: "Disprove hunt leads, complete the inventory, and write the audit result.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "candidate_b",
                    roleId: "source_falsifier",
                    task: "Independently re-read source, falsify leads, and write the audit result.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 4) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Audit both pinned source-audit candidates.",
                assignments: [
                  {
                    agentId: "audit_a",
                    roleId: "evaluation_auditor",
                    task: "Audit candidate_a, its source claims, evaluator output, diff, and trace.",
                    targetCandidateId: "candidate_a",
                  },
                  {
                    agentId: "audit_b",
                    roleId: "evaluation_auditor",
                    task: "Audit candidate_b, its source claims, evaluator output, diff, and trace.",
                    targetCandidateId: "candidate_b",
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "accept",
              summary: "Accept the highest-scoring evaluator-passing, audit-cleared result.",
              assignments: [],
              selectedCandidateId: "candidate_b",
            }),
          );
        }
        if (workflow === "exercise_solve") {
          if (this.#supervisorTurns === 1) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Map the exercise questions to bounded static observations.",
                assignments: [
                  {
                    agentId: "research_once",
                    roleId: "exercise_researcher",
                    task: "Map every question to relevant static observation IDs and gaps.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 2) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Create two independent grounded exercise answers.",
                assignments: [
                  {
                    agentId: "candidate_a",
                    roleId: "exercise_solver",
                    task: "Answer every exercise question from the bounded analyzer observations.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "candidate_b",
                    roleId: "exercise_solver",
                    task: "Independently answer every question and cite static observation IDs.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "accept",
              summary: "Accept the highest-scoring structurally grounded exercise result.",
              assignments: [],
              selectedCandidateId: "candidate_b",
            }),
          );
        }
        if (workflow === "pcap_security_triage") {
          if (this.#supervisorTurns === 1) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Run the passive packet-evidence research phase.",
                assignments: [
                  {
                    agentId: "research_once",
                    roleId: "security_evidence_researcher",
                    task: "Identify relevant packet observations, alternatives, and missing context.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          if (this.#supervisorTurns === 2) {
            return result(
              "supervisor-thread",
              JSON.stringify({
                status: "continue",
                summary: "Create two independent passive security triage candidates.",
                assignments: [
                  {
                    agentId: "candidate_a",
                    roleId: "security_analyst",
                    task: "Write a fact-grounded triage with alternatives and defensive next steps.",
                    targetCandidateId: null,
                  },
                  {
                    agentId: "candidate_b",
                    roleId: "security_analyst",
                    task: "Independently triage the bounded facts and make uncertainty explicit.",
                    targetCandidateId: null,
                  },
                ],
                selectedCandidateId: null,
              }),
            );
          }
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "accept",
              summary: "Accept the highest-scoring fact-grounded triage.",
              assignments: [],
              selectedCandidateId: "candidate_b",
            }),
          );
        }
        if (this.#supervisorTurns === 1) {
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "continue",
              summary: "Run the single read-only research phase.",
              assignments: [
                {
                  agentId: "research_once",
                  roleId: "evidence_researcher",
                  task: "Identify applicable evidence, rules, and missing facts.",
                  targetCandidateId: null,
                },
              ],
              selectedCandidateId: null,
            }),
          );
        }
        if (this.#supervisorTurns === 2) {
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "continue",
              summary: "Create two independent candidates.",
              assignments: [
                {
                  agentId: "candidate_a",
                  roleId: "diagnosis_candidate",
                  task: "Write the candidate outputs from immutable evidence.",
                  targetCandidateId: null,
                },
                {
                  agentId: "candidate_b",
                  roleId: "diagnosis_candidate",
                  task: "Write an independent candidate output.",
                  targetCandidateId: null,
                },
              ],
              selectedCandidateId: null,
            }),
          );
        }
        if (this.#supervisorTurns === 3) {
          return result(
            "supervisor-thread",
            JSON.stringify({
              status: "continue",
              summary: "Review both pinned candidate workspaces.",
              assignments: [
                {
                  agentId: "audit_a",
                  roleId: "evaluation_auditor",
                  task: "Audit candidate_a, rerun the evaluator, and inspect its scoped trace if present.",
                  targetCandidateId: "candidate_a",
                },
                {
                  agentId: "audit_b",
                  roleId: "evaluation_auditor",
                  task: "Audit candidate_b, rerun the evaluator, and inspect its scoped trace if present.",
                  targetCandidateId: "candidate_b",
                },
              ],
              selectedCandidateId: null,
            }),
          );
        }
        return result(
          "supervisor-thread",
          JSON.stringify({
            status: "accept",
            summary: "candidate_a has the highest deterministic passing coverage score.",
            assignments: [],
            selectedCandidateId: "candidate_a",
          }),
        );
      },
      catch: (cause) =>
        new RuntimeError({
          message: "Scripted Templar runtime failed",
          agentId: input.agentId,
          cause,
        }),
    });
}
