import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  assertRunId,
  createRunId,
  inspectRunState,
  listRuns,
  makeCodexRuntime,
  readRunEventRecords,
  readRunEvents,
  runOrchestration,
} from "aiur-orchestrator";
import type {
  AgentRuntime,
  PublicRunEvent,
  PublicRunView,
  RunEventRecord,
  WorkflowDefinition,
} from "aiur-orchestrator";
import { Effect, Fiber } from "effect";
import type { Fiber as EffectFiber } from "effect/Fiber";

import type { TemplarConfig } from "./config.js";
import { requiresHumanAcknowledgment, workflowEntry } from "./catalog.js";
import type { IncidentInput, PcapSecurityTriageInput } from "./contracts.js";
import { TemplarError } from "./errors.js";
import { analyzeClassicPcapFile } from "./pcap-analyzer.js";
import { PcapArtifactStore } from "./pcap-store.js";
import type { StoredPcapArtifact } from "./pcap-store.js";
import { pcapSecurityTriageWorkflow, telecomIncidentWorkflow } from "./workflow.js";
import {
  initializePcapSecurityTriageWorkspace,
  initializeTelecomIncidentWorkspace,
} from "./workspace.js";
import { DeterministicSelectionRuntime } from "./selection-guard.js";

type RunFiber = EffectFiber<unknown, unknown>;

export interface SubmitResult {
  readonly run_id: string;
  readonly run: PublicRunView;
}

export interface RunResultView {
  readonly run: PublicRunView;
  readonly result: unknown;
  readonly report: string;
  readonly evaluation: EvaluationView;
  readonly promotion: PromotionView;
}

export interface EvaluationView {
  readonly strategy: "deterministic_evaluator" | "deterministic_evaluator_with_review";
  readonly passed: boolean;
  readonly manualReviewRequired: boolean;
  readonly findings: ReadonlyArray<string>;
  readonly evaluator: EvaluationAuditView["harnessEvaluator"];
  readonly review: {
    readonly checksRerun: ReadonlyArray<string>;
    readonly suspiciousBehavior: ReadonlyArray<string>;
    readonly auditorCount: number;
    readonly traceInspected: boolean;
    readonly traceComplete: boolean;
  } | null;
}

export interface EvaluationAuditView {
  readonly checksRerun: ReadonlyArray<string>;
  readonly suspiciousBehavior: ReadonlyArray<string>;
  readonly findings: ReadonlyArray<string>;
  readonly disposition: "pass" | "manual_review";
  readonly manualAuditRequired: boolean;
  readonly candidateSelfAudit: unknown;
  readonly auditorCount: number;
  readonly traceInspected: boolean;
  readonly traceComplete: boolean;
  readonly harnessEvaluator: {
    readonly passed: boolean;
    readonly exitCode?: number;
    readonly durationMs?: number;
  } | null;
}

export interface PromotionView {
  readonly requiresHumanAcknowledgment: boolean;
  readonly reasons: ReadonlyArray<string>;
  readonly acknowledged: boolean;
  readonly eligible: boolean;
}

export class TemplarService {
  readonly config: TemplarConfig;
  readonly artifacts: PcapArtifactStore;
  readonly #runtimeFactory:
    ((runId: string, workflowId: string) => AgentRuntime | undefined) | undefined;
  readonly #active = new Map<string, RunFiber>();
  #reservedSlots = 0;

  constructor(
    config: TemplarConfig,
    options: {
      readonly runtimeFactory?: (runId: string, workflowId: string) => AgentRuntime | undefined;
    } = {},
  ) {
    this.config = config;
    this.artifacts = new PcapArtifactStore(config.artifactRoot, config.maxPcapBytes);
    this.#runtimeFactory = options.runtimeFactory;
  }

  get activeRunCount(): number {
    return this.#reservedSlots;
  }

  async initialize(): Promise<void> {
    await mkdir(path.join(this.config.templarHome, "incidents"), { recursive: true, mode: 0o700 });
    await mkdir(this.config.harnessHome, { recursive: true, mode: 0o700 });
    await this.artifacts.initialize();
  }

  async stagePcap(bytes: Uint8Array): Promise<StoredPcapArtifact> {
    return this.artifacts.stage(bytes);
  }

  async submitTelecomIncident(incident: IncidentInput): Promise<SubmitResult> {
    return this.#submit(async (runId) => {
      const pcap =
        incident.pcap_artifact_id === undefined
          ? undefined
          : await analyzeClassicPcapFile(
              await this.artifacts.resolve(incident.pcap_artifact_id),
              incident.pcap_artifact_id,
              { maxBytes: this.config.maxPcapBytes, maxPackets: this.config.maxPcapPackets },
            );
      const workspace = await initializeTelecomIncidentWorkspace({
        templarHome: this.config.templarHome,
        runId,
        incident,
        ...(pcap === undefined ? {} : { pcap }),
      });
      return { workflow: telecomIncidentWorkflow(workspace), requirePinnedAuditors: true };
    });
  }

  async submitPcapSecurityTriage(input: PcapSecurityTriageInput): Promise<SubmitResult> {
    return this.#submit(async (runId) => {
      const pcap = await analyzeClassicPcapFile(
        await this.artifacts.resolve(input.pcap_artifact_id),
        input.pcap_artifact_id,
        { maxBytes: this.config.maxPcapBytes, maxPackets: this.config.maxPcapPackets },
      );
      const workspace = await initializePcapSecurityTriageWorkspace({
        templarHome: this.config.templarHome,
        runId,
        pcap,
      });
      return {
        workflow: pcapSecurityTriageWorkflow(workspace),
        requirePinnedAuditors: false,
      };
    });
  }

  async #submit(
    prepare: (runId: string) => Promise<{
      readonly workflow: WorkflowDefinition;
      readonly requirePinnedAuditors: boolean;
    }>,
  ): Promise<SubmitResult> {
    if (this.#reservedSlots >= this.config.maxActiveRuns) {
      throw new TemplarError({
        code: "SERVICE_UNAVAILABLE",
        message: "The active run limit has been reached.",
        status: 503,
      });
    }
    this.#reservedSlots += 1;
    let started = false;
    try {
      const runId = createRunId();
      const { workflow, requirePinnedAuditors } = await prepare(runId);
      const suppliedRuntime = this.#runtimeFactory?.(runId, workflow.name);
      const runtime = new DeterministicSelectionRuntime(
        suppliedRuntime ?? makeCodexRuntime(workflow.codex),
        { requirePinnedAuditors },
      );
      const orchestration = runOrchestration({
        workflow,
        harnessHome: this.config.harnessHome,
        runId,
        apply: true,
        keepWorktrees: false,
        runtime,
      });
      const fiber = Effect.runFork(orchestration) as RunFiber;
      this.#active.set(runId, fiber);
      started = true;
      void Effect.runPromise(Fiber.await(fiber)).finally(() => {
        if (this.#active.get(runId) === fiber) {
          this.#active.delete(runId);
          this.#reservedSlots -= 1;
        }
      });
      const run = await this.#waitUntilDurable(runId, fiber);
      return { run_id: runId, run };
    } finally {
      if (!started) this.#reservedSlots -= 1;
    }
  }

  async listRuns(): Promise<ReadonlyArray<PublicRunView>> {
    return Effect.runPromise(listRuns(this.config.harnessHome));
  }

  async inspectRun(runId: string): Promise<PublicRunView> {
    assertRunId(runId);
    try {
      return await Effect.runPromise(inspectRunState(this.config.harnessHome, runId));
    } catch (cause) {
      throw new TemplarError({
        code: "NOT_FOUND",
        message: "Run was not found.",
        status: 404,
        cause,
      });
    }
  }

  async events(
    runId: string,
    afterSequence: number,
    limit = 500,
  ): Promise<ReadonlyArray<PublicRunEvent>> {
    assertRunId(runId);
    try {
      const events = await Effect.runPromise(
        readRunEvents(this.config.harnessHome, runId, { afterSequence, limit }),
      );
      return events.map(({ report: _report, runtimeError: _runtimeError, ...event }) => event);
    } catch (cause) {
      throw new TemplarError({
        code: "NOT_FOUND",
        message: "Run events were not found.",
        status: 404,
        cause,
      });
    }
  }

  async result(runId: string): Promise<RunResultView> {
    const run = await this.inspectRun(runId);
    if (run.status !== "accepted" || run.applied !== true) {
      throw new TemplarError({
        code: "CONFLICT",
        message: "The run has no accepted applied result.",
        status: 409,
      });
    }
    const root = this.incidentDirectory(runId);
    try {
      const [resultText, report, privateRecords] = await Promise.all([
        readFile(path.join(root, "result.json"), "utf8"),
        readFile(path.join(root, "report.md"), "utf8"),
        Effect.runPromise(readRunEventRecords(this.config.harnessHome, runId)),
      ]);
      const result = JSON.parse(resultText) as unknown;
      if (run.workflow === undefined) throw new Error("Accepted run is missing its workflow ID.");
      const catalogEntry = workflowEntry(run.workflow);
      const evaluationAudit = projectEvaluationAudit(
        privateRecords,
        run.selectedCandidateId,
        result,
        { traceAuditorRequired: catalogEntry.traceAuditorRequired },
      );
      const resultRecord = record(result);
      const severity =
        typeof resultRecord?.severity === "string" ? resultRecord.severity : undefined;
      const promotionRecord = record(resultRecord?.promotion);
      const reasons = requiresHumanAcknowledgment({
        family: catalogEntry.family,
        ...(severity === undefined ? {} : { severity }),
        highImpact: promotionRecord?.impact === "high",
        securityOutcome: promotionRecord?.security_outcome === true,
        headlineResult: promotionRecord?.headline_result === true,
        manualAuditRequired: evaluationAudit.manualAuditRequired,
      });
      const acknowledged = await this.#isAcknowledged(runId);
      const evaluation: EvaluationView = {
        strategy: catalogEntry.traceAuditorRequired
          ? "deterministic_evaluator_with_review"
          : "deterministic_evaluator",
        passed:
          evaluationAudit.harnessEvaluator?.passed === true && !evaluationAudit.manualAuditRequired,
        manualReviewRequired: evaluationAudit.manualAuditRequired,
        findings: evaluationAudit.findings,
        evaluator: evaluationAudit.harnessEvaluator,
        review: catalogEntry.traceAuditorRequired
          ? {
              checksRerun: evaluationAudit.checksRerun,
              suspiciousBehavior: evaluationAudit.suspiciousBehavior,
              auditorCount: evaluationAudit.auditorCount,
              traceInspected: evaluationAudit.traceInspected,
              traceComplete: evaluationAudit.traceComplete,
            }
          : null,
      };
      return {
        run,
        result,
        report,
        evaluation,
        promotion: {
          requiresHumanAcknowledgment: reasons.length > 0,
          reasons,
          acknowledged,
          eligible: reasons.length === 0 || acknowledged,
        },
      };
    } catch (cause) {
      throw new TemplarError({
        code: "INTERNAL_ERROR",
        message: "Accepted output is unavailable.",
        status: 500,
        expose: false,
        cause,
      });
    }
  }

  async acknowledgePromotion(runId: string, rationale: string): Promise<RunResultView> {
    const normalized = rationale.trim();
    if (
      normalized.length < 8 ||
      normalized.length > 500 ||
      normalized.includes(String.fromCharCode(0)) ||
      /\b(?:https?|file):\/\/|(?:^|\s)\/(?:etc|home|root|tmp|usr|var)\//iu.test(normalized)
    ) {
      throw new TemplarError({
        code: "INVALID_INPUT",
        message: "Acknowledgment rationale must contain 8-500 safe characters.",
        status: 400,
      });
    }
    const current = await this.result(runId);
    if (!current.promotion.requiresHumanAcknowledgment) {
      throw new TemplarError({
        code: "CONFLICT",
        message: "This result does not require a promotion acknowledgment.",
        status: 409,
      });
    }
    const directory = path.join(this.config.templarHome, "acknowledgements");
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const destination = path.join(directory, `${runId}.json`);
    const existing = await this.#acknowledgment(runId);
    if (existing !== undefined) {
      if (existing.rationale === normalized) return this.result(runId);
      throw new TemplarError({
        code: "CONFLICT",
        message: "The immutable promotion acknowledgment already exists.",
        status: 409,
      });
    }
    try {
      await writeFile(
        destination,
        `${JSON.stringify({ schema_version: "1", run_id: runId, acknowledged_at: new Date().toISOString(), rationale: normalized }, null, 2)}\n`,
        { encoding: "utf8", mode: 0o600, flag: "wx" },
      );
    } catch (cause) {
      if (
        typeof cause === "object" &&
        cause !== null &&
        "code" in cause &&
        cause.code === "EEXIST"
      ) {
        const raced = await this.#acknowledgment(runId);
        if (raced?.rationale === normalized) return this.result(runId);
        throw new TemplarError({
          code: "CONFLICT",
          message: "The immutable promotion acknowledgment already exists.",
          status: 409,
          cause,
        });
      }
      throw cause;
    }
    return this.result(runId);
  }

  async cancel(runId: string): Promise<PublicRunView> {
    assertRunId(runId);
    const fiber = this.#active.get(runId);
    if (fiber === undefined) {
      throw new TemplarError({
        code: "RUN_NOT_ACTIVE",
        message: "Run is not active in this process.",
        status: 409,
      });
    }
    await Effect.runPromise(Fiber.interrupt(fiber));
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const run = await this.inspectRun(runId);
      if (run.status === "interrupted" || run.status === "failed") return run;
      await new Promise<void>((resolve) => setTimeout(resolve, 20));
    }
    return this.inspectRun(runId);
  }

  incidentDirectory(runId: string): string {
    assertRunId(runId);
    return path.join(this.config.templarHome, "incidents", runId);
  }

  async #waitUntilDurable(runId: string, fiber: RunFiber): Promise<PublicRunView> {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try {
        return await Effect.runPromise(inspectRunState(this.config.harnessHome, runId));
      } catch {
        if (fiber.pollUnsafe() !== undefined) break;
        await new Promise<void>((resolve) => setTimeout(resolve, 20));
      }
    }
    throw new TemplarError({
      code: "SERVICE_UNAVAILABLE",
      message: "Run did not become durably observable.",
      status: 503,
    });
  }

  async #isAcknowledged(runId: string): Promise<boolean> {
    return (await this.#acknowledgment(runId)) !== undefined;
  }

  async #acknowledgment(
    runId: string,
  ): Promise<{ readonly run_id: string; readonly rationale?: string } | undefined> {
    try {
      const parsed = record(
        JSON.parse(
          await readFile(
            path.join(this.config.templarHome, "acknowledgements", `${runId}.json`),
            "utf8",
          ),
        ),
      );
      if (parsed?.run_id !== runId) return undefined;
      return {
        run_id: runId,
        ...(typeof parsed.rationale === "string" ? { rationale: parsed.rationale } : {}),
      };
    } catch (cause) {
      if (typeof cause === "object" && cause !== null && "code" in cause && cause.code === "ENOENT")
        return undefined;
      throw cause;
    }
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function unique(values: ReadonlyArray<string>): ReadonlyArray<string> {
  return [...new Set(values)].sort();
}

function marker(value: string, prefix: string): string | undefined {
  return value.startsWith(prefix) ? value.slice(prefix.length).trim() : undefined;
}

export interface EvaluationProjectionOptions {
  readonly traceAuditorRequired?: boolean;
}

export function projectEvaluationAudit(
  events: ReadonlyArray<RunEventRecord>,
  selectedCandidateId: string | undefined,
  candidateResult: unknown,
  options: EvaluationProjectionOptions = {},
): EvaluationAuditView {
  const checks: Array<string> = [];
  const suspicious: Array<string> = [];
  const findings: Array<string> = [];
  let manualAuditRequired = false;
  let auditorCount = 0;
  let traceInspected = false;
  let traceComplete = false;
  let harnessEvaluator: EvaluationAuditView["harnessEvaluator"] = null;
  for (const event of events) {
    if (event.type !== "candidate.snapshot" || event.candidateId !== selectedCandidateId) continue;
    const evaluation = record(event.evaluation);
    if (evaluation === undefined || typeof evaluation.passed !== "boolean") continue;
    harnessEvaluator = {
      passed: evaluation.passed,
      ...(typeof evaluation.exitCode === "number" ? { exitCode: evaluation.exitCode } : {}),
      ...(typeof evaluation.durationMs === "number" ? { durationMs: evaluation.durationMs } : {}),
    };
  }
  if (options.traceAuditorRequired === false) {
    const evaluatorPassed = harnessEvaluator?.passed === true;
    return {
      checksRerun: evaluatorPassed ? ["deterministic_evaluator"] : [],
      suspiciousBehavior: [],
      findings: evaluatorPassed
        ? []
        : ["The selected candidate has no persisted passing harness evaluation."],
      disposition: evaluatorPassed ? "pass" : "manual_review",
      manualAuditRequired: !evaluatorPassed,
      candidateSelfAudit: undefined,
      auditorCount: 0,
      traceInspected: false,
      traceComplete: false,
      harnessEvaluator,
    };
  }
  const traceRecords = events.filter(
    (event) =>
      event.type === "harness.private.audit_materialized" &&
      event.candidateId === selectedCandidateId,
  );
  if (traceRecords.length === 0) {
    manualAuditRequired = true;
    findings.push(
      "No trusted candidate-scoped audit trace was materialized for the selected candidate.",
    );
  } else if (traceRecords.some((event) => event.truncated === true)) {
    manualAuditRequired = true;
    findings.push(
      "The trusted candidate-scoped audit trace was truncated; audit coverage is degraded.",
    );
  } else {
    traceComplete = true;
  }
  for (const event of events) {
    if (
      event.type !== "agent.turn_completed" ||
      event.roleId !== "evaluation_auditor" ||
      (selectedCandidateId !== undefined && event.targetCandidateId !== selectedCandidateId)
    )
      continue;
    const report = record(event.report);
    auditorCount += 1;
    if (report === undefined || report.status !== "completed") {
      manualAuditRequired = true;
      traceComplete = false;
      findings.push("The selected candidate auditor report was absent or malformed.");
      continue;
    }
    const evidence = Array.isArray(report.evidence)
      ? report.evidence.filter((item): item is string => typeof item === "string")
      : [];
    let sawChecks = false;
    let sawBehavior = false;
    let sawFinding = false;
    let sawDisposition = false;
    let sawManual = false;
    let sawTrace = false;
    let sawTraceComplete = false;
    for (const item of evidence) {
      const rerun = marker(item, "audit.checks_rerun=");
      if (rerun !== undefined) {
        sawChecks = true;
        checks.push(
          ...rerun
            .split(",")
            .map((part) => part.trim())
            .filter(Boolean),
        );
      }
      const behavior = marker(item, "audit.suspicious_behavior=");
      if (behavior !== undefined) {
        sawBehavior = true;
        if (behavior !== "none")
          suspicious.push(
            ...behavior
              .split(",")
              .map((part) => part.trim())
              .filter(Boolean),
          );
      }
      const finding = marker(item, "audit.finding=");
      if (finding !== undefined) {
        sawFinding = true;
        if (finding.length > 0) findings.push(finding);
      }
      const disposition = marker(item, "audit.disposition=");
      if (disposition !== undefined) {
        sawDisposition = true;
        if (disposition === "manual_review") manualAuditRequired = true;
        else if (disposition !== "pass") {
          manualAuditRequired = true;
          findings.push("The evaluation auditor emitted an invalid disposition marker.");
        }
      }
      const required = marker(item, "audit.manualAuditRequired=");
      if (required !== undefined) {
        sawManual = true;
        if (required === "true") manualAuditRequired = true;
        else if (required !== "false") {
          manualAuditRequired = true;
          findings.push("The evaluation auditor emitted an invalid manual-audit marker.");
        }
      }
      const trace = marker(item, "audit.trace_inspected=");
      if (trace !== undefined) {
        sawTrace = true;
        if (trace === "true") traceInspected = true;
        else if (trace === "false") {
          manualAuditRequired = true;
          traceComplete = false;
        } else {
          manualAuditRequired = true;
          traceComplete = false;
          findings.push("The evaluation auditor emitted an invalid trace marker.");
        }
      }
      const complete = marker(item, "audit.trace_complete=");
      if (complete !== undefined) {
        sawTraceComplete = true;
        if (complete === "false") {
          manualAuditRequired = true;
          traceComplete = false;
        } else if (complete !== "true") {
          manualAuditRequired = true;
          traceComplete = false;
          findings.push("The evaluation auditor emitted an invalid trace-completeness marker.");
        }
      }
    }
    if (!sawChecks || !checks.includes("deterministic_evaluator")) {
      manualAuditRequired = true;
      findings.push(
        "The evaluation auditor did not attest an empirical deterministic-evaluator rerun.",
      );
    }
    if (
      !sawBehavior ||
      !sawFinding ||
      !sawDisposition ||
      !sawManual ||
      !sawTrace ||
      !sawTraceComplete
    ) {
      manualAuditRequired = true;
      if (!sawTrace || !sawTraceComplete) traceComplete = false;
      findings.push(
        "The evaluation auditor omitted one or more required structured audit markers.",
      );
    }
    if (Array.isArray(report.risks)) {
      findings.push(...report.risks.filter((item): item is string => typeof item === "string"));
    }
  }
  if (auditorCount === 0) {
    manualAuditRequired = true;
    traceComplete = false;
    findings.push(
      "No independent evaluation-auditor report was persisted for the selected candidate.",
    );
  }
  const candidateSelfAudit = record(candidateResult)?.evaluationAudit;
  const candidateAuditRecord = record(candidateSelfAudit);
  if (
    candidateAuditRecord?.manualAuditRequired === true ||
    candidateAuditRecord?.disposition === "manual_review"
  ) {
    manualAuditRequired = true;
    findings.push("The candidate self-audit requested manual review.");
  }
  if (Array.isArray(candidateAuditRecord?.suspicious_behavior)) {
    suspicious.push(
      ...candidateAuditRecord.suspicious_behavior.filter(
        (item): item is string => typeof item === "string" && item.length > 0,
      ),
    );
  }
  if (harnessEvaluator?.passed !== true) {
    manualAuditRequired = true;
    findings.push(
      "The selected candidate has no persisted passing independent harness evaluation.",
    );
  }
  return {
    checksRerun: unique(checks),
    suspiciousBehavior: unique(suspicious),
    findings: unique(findings),
    disposition: manualAuditRequired || suspicious.length > 0 ? "manual_review" : "pass",
    manualAuditRequired: manualAuditRequired || suspicious.length > 0,
    candidateSelfAudit,
    auditorCount,
    traceInspected,
    traceComplete,
    harnessEvaluator,
  };
}
