import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  assertRunId,
  createRunId,
  readRunEventRecords,
} from "@agentic-orch/agent-blocks/persistence";
import type { RunEventRecord } from "@agentic-orch/agent-blocks/persistence";
import {
  inspectRunState,
  listRuns,
  readRunEvents,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree/control-plane";
import type {
  PublicRunEvent,
  PublicRunView,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree/control-plane";
import {
  makeCodexRuntime,
  runOrchestration,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import type {
  AgentRuntime,
  WorkflowDefinition,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import { Effect, Fiber } from "effect";
import type { Fiber as EffectFiber } from "effect/Fiber";

import type { TemplarConfig } from "./config.js";
import { requiresHumanAcknowledgment, workflowEntry } from "./catalog.js";
import type {
  ExerciseSolveInput,
  IncidentInput,
  PcapSecurityTriageInput,
  SourceSecurityAuditInput,
  SourceSecurityFixInput,
} from "./contracts.js";
import { isSourceSnapshotId } from "./contracts.js";
import { DroneClient, droneUnavailableStatus } from "./drone-client.js";
import type { DroneJob, DroneProviderStatus } from "./drone-client.js";
import { TemplarError } from "./errors.js";
import { ExerciseSnapshotStore } from "./exercise-store.js";
import type { StoredExerciseSnapshot } from "./exercise-store.js";
import { analyzeClassicPcapBytes } from "./pcap-analyzer.js";
import { PcapArtifactStore } from "./pcap-store.js";
import type { StoredPcapArtifact } from "./pcap-store.js";
import { SourceSnapshotStore } from "./source-store.js";
import type { StoredSourceSnapshot } from "./source-store.js";
import { buildSourceFixContext, decodeSourceAuditReference } from "./source-fix.js";
import {
  assertSourceValidationOperation,
  buildSourceValidationArtifact,
  SOURCE_VALIDATION_INPUT_SLOT,
  SOURCE_VALIDATION_MEDIA_TYPE,
  validationRationale,
} from "./source-validation.js";
import {
  exerciseSolveWorkflow,
  pcapSecurityTriageWorkflow,
  sourceSecurityAuditWorkflow,
  sourceSecurityFixWorkflow,
  telecomIncidentWorkflow,
} from "./workflow.js";
import {
  initializeExerciseSolveWorkspace,
  initializePcapSecurityTriageWorkspace,
  initializeSourceSecurityAuditWorkspace,
  initializeSourceSecurityFixWorkspace,
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

export interface SourceFixValidationRequestView {
  readonly schema_version: "1";
  readonly run_id: string;
  readonly operation_id: string;
  readonly source_artifact_id: string;
  readonly job_id: string;
  readonly requested_at: string;
  readonly rationale: string;
}

export interface SourceFixValidationView {
  readonly request: SourceFixValidationRequestView;
  readonly job: DroneJob;
}

type TemplarDroneClient = Pick<
  DroneClient,
  "providers" | "operations" | "stageArtifact" | "submitJob" | "job"
>;

export class TemplarService {
  readonly config: TemplarConfig;
  readonly artifacts: PcapArtifactStore;
  readonly exercises: ExerciseSnapshotStore;
  readonly sources: SourceSnapshotStore;
  readonly #runtimeFactory:
    ((runId: string, workflowId: string) => AgentRuntime | undefined) | undefined;
  readonly #drone: TemplarDroneClient;
  readonly #active = new Map<string, RunFiber>();
  readonly #validationSubmissions = new Map<string, Promise<SourceFixValidationView>>();
  #reservedSlots = 0;

  constructor(
    config: TemplarConfig,
    options: {
      readonly runtimeFactory?: (runId: string, workflowId: string) => AgentRuntime | undefined;
      readonly droneClient?: TemplarDroneClient;
    } = {},
  ) {
    this.config = config;
    this.artifacts = new PcapArtifactStore(config.artifactRoot, config.maxPcapBytes);
    this.exercises = new ExerciseSnapshotStore(
      config.exerciseArtifactRoot,
      config.maxExerciseSnapshotBytes,
    );
    this.sources = new SourceSnapshotStore(
      config.sourceArtifactRoot,
      config.maxSourceSnapshotBytes,
    );
    this.#runtimeFactory = options.runtimeFactory;
    this.#drone =
      options.droneClient ??
      new DroneClient({
        baseUrl: config.droneUrl,
        ...(config.droneToken === undefined ? {} : { token: config.droneToken }),
        timeoutMs: config.droneTimeoutMs,
      });
  }

  get activeRunCount(): number {
    return this.#reservedSlots;
  }

  async initialize(): Promise<void> {
    await mkdir(path.join(this.config.templarHome, "incidents"), { recursive: true, mode: 0o700 });
    await mkdir(this.config.harnessHome, { recursive: true, mode: 0o700 });
    await this.artifacts.initialize();
    await this.exercises.initialize();
    await this.sources.initialize();
  }

  async stagePcap(bytes: Uint8Array): Promise<StoredPcapArtifact> {
    return this.artifacts.stage(bytes);
  }

  async stageExerciseSnapshot(value: unknown): Promise<StoredExerciseSnapshot> {
    return this.exercises.stage(value);
  }

  async stageSourceSnapshot(value: unknown): Promise<StoredSourceSnapshot> {
    return this.sources.stage(value);
  }

  async labProviders(): Promise<ReadonlyArray<DroneProviderStatus>> {
    if (!this.config.droneEnabled) return [droneUnavailableStatus("disabled_by_configuration")];
    try {
      return await this.#drone.providers();
    } catch {
      return [droneUnavailableStatus("service_unavailable")];
    }
  }

  async submitTelecomIncident(incident: IncidentInput): Promise<SubmitResult> {
    return this.#submit(async (runId) => {
      const pcap =
        incident.pcap_artifact_id === undefined
          ? undefined
          : analyzeClassicPcapBytes(
              await this.artifacts.read(incident.pcap_artifact_id),
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
      const pcap = analyzeClassicPcapBytes(
        await this.artifacts.read(input.pcap_artifact_id),
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

  async submitExerciseSolve(input: ExerciseSolveInput): Promise<SubmitResult> {
    return this.#submit(async (runId) => {
      const snapshot = await this.exercises.resolve(input.exercise_snapshot_id);
      const workspace = await initializeExerciseSolveWorkspace({
        templarHome: this.config.templarHome,
        runId,
        snapshot,
      });
      return {
        workflow: exerciseSolveWorkflow(workspace),
        requirePinnedAuditors: false,
      };
    });
  }

  async submitSourceSecurityAudit(input: SourceSecurityAuditInput): Promise<SubmitResult> {
    return this.#submit(async (runId) => {
      const snapshot = await this.sources.resolve(input.source_snapshot_id);
      const workspace = await initializeSourceSecurityAuditWorkspace({
        templarHome: this.config.templarHome,
        runId,
        sourceSnapshotId: input.source_snapshot_id,
        snapshot,
      });
      return {
        workflow: sourceSecurityAuditWorkflow(workspace),
        requirePinnedAuditors: true,
      };
    });
  }

  async submitSourceSecurityFix(input: SourceSecurityFixInput): Promise<SubmitResult> {
    const audit = await this.result(input.audit_run_id);
    if (audit.run.workflow !== "source_security_audit" || !audit.evaluation.passed) {
      throw new TemplarError({
        code: "CONFLICT",
        message: "A source fix requires an accepted, evaluation-passing source security audit.",
        status: 409,
      });
    }
    const reference = decodeSourceAuditReference(
      JSON.parse(
        await readFile(
          path.join(this.incidentDirectory(input.audit_run_id), "source-metadata.json"),
          "utf8",
        ),
      ) as unknown,
    );
    const snapshot = await this.sources.resolve(reference.source_snapshot_id);
    if (JSON.stringify(snapshot.repository) !== JSON.stringify(reference.repository)) {
      throw new TemplarError({
        code: "CONFLICT",
        message: "The accepted audit no longer matches its content-addressed source snapshot.",
        status: 409,
      });
    }
    const context = buildSourceFixContext({
      sourceAuditRunId: input.audit_run_id,
      sourceSnapshotId: reference.source_snapshot_id,
      snapshot,
      auditResult: audit.result,
    });
    return this.#submit(async (runId) => {
      const workspace = await initializeSourceSecurityFixWorkspace({
        templarHome: this.config.templarHome,
        runId,
        snapshot,
        context,
      });
      return {
        workflow: sourceSecurityFixWorkflow(workspace),
        requirePinnedAuditors: true,
      };
    });
  }

  async submitSourceFixValidation(
    runId: string,
    rationale: string,
  ): Promise<SourceFixValidationView> {
    assertRunId(runId);
    const inFlight = this.#validationSubmissions.get(runId);
    if (inFlight !== undefined) return inFlight;
    const submission = this.#submitSourceFixValidation(runId, rationale).finally(() => {
      this.#validationSubmissions.delete(runId);
    });
    this.#validationSubmissions.set(runId, submission);
    return submission;
  }

  async #submitSourceFixValidation(
    runId: string,
    rationale: string,
  ): Promise<SourceFixValidationView> {
    const operationId = this.config.droneSourceValidationOperationId;
    if (!this.config.droneEnabled || operationId === undefined) {
      throw new TemplarError({
        code: "CONFLICT",
        message: "Drone source validation is not explicitly configured.",
        status: 409,
      });
    }
    const normalizedRationale = validationRationale(rationale);
    const current = await this.result(runId);
    if (
      current.run.workflow !== "source_security_fix" ||
      !current.evaluation.passed ||
      !current.promotion.acknowledged
    ) {
      throw new TemplarError({
        code: "CONFLICT",
        message:
          "Drone replay requires an accepted source fix, a passing evaluation, and promotion acknowledgment.",
        status: 409,
      });
    }
    const existing = await this.#sourceValidationRequest(runId);
    if (existing !== undefined) {
      if (existing.rationale !== normalizedRationale) {
        throw new TemplarError({
          code: "CONFLICT",
          message: "An immutable Drone validation request already exists for this source fix.",
          status: 409,
        });
      }
      return this.sourceFixValidation(runId);
    }

    const workflow = record(
      JSON.parse(
        await readFile(path.join(this.incidentDirectory(runId), "workflow.json"), "utf8"),
      ) as unknown,
    );
    const sourceSnapshotId = workflow?.source_snapshot_id;
    if (typeof sourceSnapshotId !== "string" || !isSourceSnapshotId(sourceSnapshotId)) {
      throw new TemplarError({
        code: "INTERNAL_ERROR",
        message: "Accepted source-fix metadata is invalid.",
        status: 500,
        expose: false,
      });
    }
    const snapshot = await this.sources.resolve(sourceSnapshotId);
    const artifactBytes = await buildSourceValidationArtifact({
      targetRoot: path.join(this.incidentDirectory(runId), "target"),
      repository: snapshot.repository,
      maximumBytes: this.config.maxSourceSnapshotBytes,
    });
    const operation = (await this.#drone.operations()).find(
      (candidate) => candidate.operation_id === operationId,
    );
    if (operation === undefined) {
      throw new TemplarError({
        code: "CONFLICT",
        message: "The configured Drone source-validation operation is unavailable.",
        status: 409,
      });
    }
    assertSourceValidationOperation(operation, artifactBytes.byteLength);
    const artifact = await this.#drone.stageArtifact(artifactBytes, SOURCE_VALIDATION_MEDIA_TYPE);
    const job = await this.#drone.submitJob({
      schema_version: "1",
      operation_id: operationId,
      inputs: { [SOURCE_VALIDATION_INPUT_SLOT]: artifact.artifact_id },
    });
    const request: SourceFixValidationRequestView = {
      schema_version: "1",
      run_id: runId,
      operation_id: operationId,
      source_artifact_id: artifact.artifact_id,
      job_id: job.job_id,
      requested_at: job.submitted_at,
      rationale: normalizedRationale,
    };
    try {
      await writeFile(
        path.join(this.incidentDirectory(runId), "source-validation-request.json"),
        `${JSON.stringify(request, null, 2)}\n`,
        { encoding: "utf8", mode: 0o600, flag: "wx" },
      );
    } catch (cause) {
      if (
        typeof cause === "object" &&
        cause !== null &&
        "code" in cause &&
        cause.code === "EEXIST"
      ) {
        const raced = await this.#sourceValidationRequest(runId);
        if (raced?.rationale === normalizedRationale) return this.sourceFixValidation(runId);
        throw new TemplarError({
          code: "CONFLICT",
          message: "An immutable Drone validation request already exists for this source fix.",
          status: 409,
          cause,
        });
      }
      throw cause;
    }
    return { request, job };
  }

  async sourceFixValidation(runId: string): Promise<SourceFixValidationView> {
    assertRunId(runId);
    if (!this.config.droneEnabled) {
      throw new TemplarError({
        code: "SERVICE_UNAVAILABLE",
        message: "Drone is disabled.",
        status: 503,
      });
    }
    const request = await this.#sourceValidationRequest(runId);
    if (request === undefined) {
      throw new TemplarError({
        code: "NOT_FOUND",
        message: "No Drone validation request exists for this source fix.",
        status: 404,
      });
    }
    const job = await this.#drone.job(request.job_id);
    if (
      job.operation_id !== request.operation_id ||
      job.inputs[SOURCE_VALIDATION_INPUT_SLOT] !== request.source_artifact_id
    ) {
      throw new TemplarError({
        code: "SERVICE_UNAVAILABLE",
        message: "Drone returned an unrelated validation job.",
        status: 503,
        expose: false,
      });
    }
    return { request, job };
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

  async #sourceValidationRequest(
    runId: string,
  ): Promise<SourceFixValidationRequestView | undefined> {
    try {
      const parsed = record(
        JSON.parse(
          await readFile(
            path.join(this.incidentDirectory(runId), "source-validation-request.json"),
            "utf8",
          ),
        ) as unknown,
      );
      const keys = parsed === undefined ? [] : Object.keys(parsed).sort();
      const expected = [
        "job_id",
        "operation_id",
        "rationale",
        "requested_at",
        "run_id",
        "schema_version",
        "source_artifact_id",
      ].sort();
      if (
        parsed?.schema_version !== "1" ||
        parsed.run_id !== runId ||
        JSON.stringify(keys) !== JSON.stringify(expected) ||
        typeof parsed.operation_id !== "string" ||
        !/^[a-z][a-z0-9_.-]{0,127}$/u.test(parsed.operation_id) ||
        typeof parsed.source_artifact_id !== "string" ||
        !/^sha256_[a-f0-9]{64}$/u.test(parsed.source_artifact_id) ||
        typeof parsed.job_id !== "string" ||
        !/^job_[a-f0-9]{32}$/u.test(parsed.job_id) ||
        typeof parsed.requested_at !== "string" ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(parsed.requested_at) ||
        typeof parsed.rationale !== "string"
      ) {
        throw new Error("Stored source validation request is malformed.");
      }
      return parsed as unknown as SourceFixValidationRequestView;
    } catch (cause) {
      if (
        typeof cause === "object" &&
        cause !== null &&
        "code" in cause &&
        cause.code === "ENOENT"
      ) {
        return undefined;
      }
      if (cause instanceof TemplarError) throw cause;
      throw new TemplarError({
        code: "INTERNAL_ERROR",
        message: "Stored source validation request is unavailable.",
        status: 500,
        expose: false,
        cause,
      });
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
