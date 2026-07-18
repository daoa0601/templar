import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import {
  APPLE_NATIVE_ATTESTATION_PROFILE,
  decodeDroneExecutionAttestation,
  normalizeDroneMediaType,
} from "@agentic-orch/drone-client";
import type {
  DroneArtifactDownload,
  DroneArtifactMetadata,
  DroneJob,
  DroneJobSubmission,
  DroneProviderAttestationSummary,
  DroneProviderStatus,
  DronePublicOperation,
} from "@agentic-orch/drone-client";

import type { TemplarConfig } from "./config.js";
import { courseChecksForAnalysisMode, decodeCourseAssignmentEvidence } from "./course-evidence.js";
import type { CourseAssignmentEvidence } from "./course-evidence.js";
import { loadCourseCorpusManifest } from "./course-corpus.js";
import type {
  CourseAnalysisMode,
  CourseCorpusArtifact,
  CourseCorpusAssignment,
  CourseCorpusManifest,
} from "./course-corpus.js";
import { invalidInput, TemplarError } from "./errors.js";
import { COURSE_ASSIGNMENT_EVIDENCE_MEDIA_TYPE, decodeExerciseSnapshot } from "./exercise.js";
import type { ExerciseSnapshot } from "./exercise.js";

export const COURSE_LAB_CONTEXT_MEDIA_TYPE = "application/vnd.templar.course-lab-context+json";
export const COURSE_LAB_EVIDENCE_MEDIA_TYPE =
  "application/vnd.templar.course-assignment-evidence+json";
export const DRONE_EXECUTION_ATTESTATION_MEDIA_TYPE =
  "application/vnd.drone.execution-attestation+json";
export const COURSE_LAB_ANALYZER_ID = "templar_drone_course_lab";
export const COURSE_LAB_ANALYZER_VERSION = "1.0.0";

const LAB_ID = /^lab_[a-f0-9]{32}$/u;
const ARTIFACT_ID = /^sha256_[a-f0-9]{64}$/u;
const JOB_ID = /^job_[a-f0-9]{32}$/u;
const ATTESTATION_ID = /^attestation\.sha256\.[a-f0-9]{64}$/u;
const ATTESTATION_KEY_ID = /^ed25519\.sha256\.[a-f0-9]{64}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const SAFE_ID = /^[a-z][a-z0-9_.-]{0,127}$/u;
const UTC_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const MAX_RECORD_BYTES = 128 * 1024;
const ANALYSIS_MODES = new Set<CourseAnalysisMode>([
  "windows_forensics",
  "native_static",
  "native_dynamic_semantics",
  "dotnet_reverse_engineering",
  "dotnet_batch",
]);

export interface CourseLabDroneClient {
  readonly providers: () => Promise<ReadonlyArray<DroneProviderStatus>>;
  readonly operations: () => Promise<ReadonlyArray<DronePublicOperation>>;
  readonly stageArtifact: (bytes: Uint8Array, mediaType: string) => Promise<DroneArtifactMetadata>;
  readonly submitJob: (input: DroneJobSubmission) => Promise<DroneJob>;
  readonly job: (jobId: string) => Promise<DroneJob>;
  readonly artifactContent: (artifactId: string) => Promise<DroneArtifactDownload>;
}

export interface CourseLabApprovalRecord {
  readonly schema_version: "1";
  readonly lab_id: string;
  readonly corpus_id: string;
  readonly assignment_id: string;
  readonly source_artifact_id: string;
  readonly analysis_mode: CourseAnalysisMode;
  readonly operation_id: string;
  readonly provider_attestation: DroneProviderAttestationSummary;
  readonly specimen_sha256: string;
  readonly specimen_size_bytes: number;
  readonly specimen_media_type: string;
  readonly exact_source_artifact: boolean;
  readonly context_sha256: string;
  readonly rationale: string;
  readonly approved_at: string;
}

export interface CourseLabSubmissionRecord {
  readonly schema_version: "1";
  readonly lab_id: string;
  readonly job_id: string;
  readonly operation_id: string;
  readonly provider_attestation_id: string;
  readonly specimen_artifact_id: string;
  readonly context_artifact_id: string;
  readonly submitted_at: string;
}

export interface CourseLabStatus {
  readonly approval: CourseLabApprovalRecord;
  readonly submission: CourseLabSubmissionRecord;
  readonly job: DroneJob;
}

export interface CourseLabCollection {
  readonly schema_version: "1";
  readonly lab_id: string;
  readonly assignment_id: string;
  readonly evidence_artifact_id: string;
  readonly evidence_sha256: string;
  readonly execution_attestation_artifact_id: string;
  readonly provider_attestation_id: string;
  readonly collected_at: string;
}

interface CourseLabContext {
  readonly schema_version: "1";
  readonly profile: "templar_course_assignment_lab_v1";
  readonly corpus_id: string;
  readonly assignment_id: string;
  readonly source_artifact_id: string;
  readonly analysis_mode: CourseAnalysisMode;
  readonly requirement_ids: ReadonlyArray<string>;
  readonly required_check_ids: ReadonlyArray<string>;
  readonly assignment_artifact_ids: ReadonlyArray<string>;
  readonly specimen: {
    readonly sha256: string;
    readonly size_bytes: number;
    readonly media_type: string;
    readonly exact_source_artifact: boolean;
  };
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function conflict(message: string, cause?: unknown): TemplarError {
  return new TemplarError({ code: "CONFLICT", message, status: 409, cause });
}

function unavailable(message: string, cause?: unknown): TemplarError {
  return new TemplarError({
    code: "SERVICE_UNAVAILABLE",
    message,
    status: 503,
    expose: false,
    cause,
  });
}

function normalizedRationale(value: string): string {
  const rationale = value.trim();
  const unsafeControl = [...rationale].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return (code < 32 && code !== 9 && code !== 10 && code !== 13) || code === 127;
  });
  if (rationale.length < 16 || rationale.length > 1_000 || unsafeControl) {
    throw invalidInput("Course-lab approval rationale must contain 16-1000 safe characters.");
  }
  return rationale;
}

function approvedAttestationId(value: string): string {
  if (!ATTESTATION_ID.test(value)) {
    throw invalidInput("The approved provider attestation ID is invalid.");
  }
  return value;
}

function labId(value: string): string {
  if (!LAB_ID.test(value)) throw invalidInput("Course lab ID is invalid.");
  return value;
}

function sameMembers(left: ReadonlyArray<string>, right: ReadonlyArray<string>): boolean {
  return (
    left.length === right.length &&
    [...left].sort().every((value, index) => value === [...right].sort()[index])
  );
}

function exactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: ReadonlyArray<string>,
): boolean {
  return JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
}

function canonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !UTC_TIMESTAMP.test(value)) return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
}

async function privateDirectory(directory: string): Promise<void> {
  const info = await lstat(directory);
  const owned = typeof process.geteuid !== "function" || info.uid === process.geteuid();
  if (!info.isDirectory() || info.isSymbolicLink() || !owned || (info.mode & 0o077) !== 0) {
    throw unavailable("Course-lab custody directory is not private and owned.");
  }
}

async function boundedFile(file: string, maximum: number): Promise<Buffer> {
  const handle = await open(path.resolve(file), constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size <= 0n || before.size > BigInt(maximum)) {
      throw invalidInput(`Course-lab specimen must be a 1-${maximum} byte regular file.`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      BigInt(bytes.byteLength) !== before.size ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    ) {
      throw invalidInput("Course-lab specimen changed while it was read.");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function recordFile(file: string): Promise<Readonly<Record<string, unknown>>> {
  const bytes = await boundedFile(file, MAX_RECORD_BYTES);
  const value = JSON.parse(bytes.toString("utf8")) as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Course-lab record must be an object.");
  }
  return value as Readonly<Record<string, unknown>>;
}

function normalizeSpecimenMediaType(value: string): string {
  try {
    return normalizeDroneMediaType(value);
  } catch (cause) {
    throw invalidInput("Course-lab specimen media type is invalid.", cause);
  }
}

function findSource(
  manifest: CourseCorpusManifest,
  sourceArtifactId: string,
): { readonly artifact: CourseCorpusArtifact; readonly assignment: CourseCorpusAssignment } {
  if (!SAFE_ID.test(sourceArtifactId)) {
    throw invalidInput("Course source artifact ID is invalid.");
  }
  const artifact = manifest.artifacts.find(
    (candidate) => candidate.artifact_id === sourceArtifactId,
  );
  if (artifact === undefined) throw invalidInput("Course source artifact is not in the manifest.");
  const assignment = manifest.assignments.find(
    (candidate) => candidate.assignment_id === artifact.assignment_id,
  );
  if (assignment === undefined) throw new Error("Course manifest assignment is missing.");
  return { artifact, assignment };
}

function assertProvider(
  providers: ReadonlyArray<DroneProviderStatus>,
  approvedId: string,
  now = new Date(),
): DroneProviderAttestationSummary {
  const provider = providers.find((candidate) => candidate.provider_id === "apple_native");
  if (
    provider === undefined ||
    !provider.installed ||
    !provider.enabled ||
    !provider.mutations_available ||
    !provider.attested ||
    provider.attestation === undefined ||
    provider.attestation.profile !== APPLE_NATIVE_ATTESTATION_PROFILE ||
    provider.attestation.attestation_id !== approvedId ||
    new Date(provider.attestation.expires_at).valueOf() <= now.valueOf()
  ) {
    throw conflict(
      "Course-lab submission requires the currently admitted Apple no-network VM attestation.",
    );
  }
  return provider.attestation;
}

function assertOperation(
  operation: DronePublicOperation | undefined,
  specimenMediaType: string,
  specimenBytes: number,
  contextBytes: number,
): DronePublicOperation {
  const inputs = operation?.inputs ?? [];
  const outputs = operation?.outputs ?? [];
  const specimen = inputs.find((input) => input.name === "specimen");
  const context = inputs.find((input) => input.name === "context");
  const evidence = outputs.find((output) => output.name === "evidence");
  if (
    operation === undefined ||
    !operation.enabled ||
    operation.provider !== "apple_native" ||
    operation.network !== "none" ||
    inputs.length !== 2 ||
    outputs.length !== 1 ||
    specimen === undefined ||
    !specimen.required ||
    specimen.max_bytes < specimenBytes ||
    !specimen.media_types.includes(specimenMediaType) ||
    context === undefined ||
    !context.required ||
    context.max_bytes < contextBytes ||
    !context.media_types.includes(COURSE_LAB_CONTEXT_MEDIA_TYPE) ||
    evidence === undefined ||
    !evidence.required ||
    evidence.media_type !== COURSE_LAB_EVIDENCE_MEDIA_TYPE
  ) {
    throw conflict("Configured Drone operation does not satisfy the strict course-lab contract.");
  }
  return operation;
}

function validateAssignmentEvidence(
  value: unknown,
  assignment: CourseCorpusAssignment,
): ReadonlyArray<CourseAssignmentEvidence> {
  const evidence = decodeCourseAssignmentEvidence(value);
  if (evidence.length !== 1 || evidence[0]?.assignment_id !== assignment.assignment_id) {
    throw unavailable("Course-lab evidence does not match the approved assignment.");
  }
  const item = evidence[0];
  if (
    !sameMembers(
      item.questions.map((question) => question.question_id),
      assignment.requirement_ids,
    ) ||
    !sameMembers(item.check_ids, courseChecksForAnalysisMode(assignment.analysis_mode)) ||
    item.observations.length === 0 ||
    item.observations.some(
      (observation) =>
        !observation.observation_id.startsWith(`${assignment.assignment_id}.observation.`) ||
        observation.artifact_ids.length === 0 ||
        observation.artifact_ids.some(
          (artifactId) => !assignment.artifact_ids.includes(artifactId),
        ),
    )
  ) {
    throw unavailable("Course-lab evidence violates the course manifest boundary.");
  }
  return evidence;
}

export function assertCourseLabExerciseSnapshot(
  snapshot: ExerciseSnapshot,
  manifest: CourseCorpusManifest,
): void {
  if (
    snapshot.artifact.media_type !== COURSE_ASSIGNMENT_EVIDENCE_MEDIA_TYPE ||
    snapshot.analyzer.analyzer_id !== COURSE_LAB_ANALYZER_ID ||
    snapshot.analyzer.version !== COURSE_LAB_ANALYZER_VERSION
  ) {
    throw invalidInput("The exercise is not a recognized attested course-assignment snapshot.");
  }
  const assignment = manifest.assignments.find(
    (candidate) =>
      snapshot.exercise_id === `course-assignment.${manifest.corpus_id}.${candidate.assignment_id}`,
  );
  if (
    assignment === undefined ||
    snapshot.title !== `${assignment.title} — attested passive evidence` ||
    !sameMembers(
      snapshot.questions.map((question) => question.question_id),
      assignment.requirement_ids,
    ) ||
    !sameMembers(
      snapshot.available_checks,
      courseChecksForAnalysisMode(assignment.analysis_mode),
    ) ||
    !snapshot.observations.some(
      (observation) =>
        observation.observation_id ===
          `${assignment.assignment_id}.observation.execution-provenance` &&
        observation.kind === "execution_attestation" &&
        observation.required,
    ) ||
    snapshot.observations.some(
      (observation) =>
        !observation.observation_id.startsWith(`${assignment.assignment_id}.observation.`),
    )
  ) {
    throw invalidInput("The attested course-assignment snapshot violates the corpus boundary.");
  }
}

function decodeApproval(
  value: Readonly<Record<string, unknown>>,
  expectedLabId: string,
): CourseLabApprovalRecord {
  const attestation = value.provider_attestation;
  if (
    !exactKeys(value, [
      "schema_version",
      "lab_id",
      "corpus_id",
      "assignment_id",
      "source_artifact_id",
      "analysis_mode",
      "operation_id",
      "provider_attestation",
      "specimen_sha256",
      "specimen_size_bytes",
      "specimen_media_type",
      "exact_source_artifact",
      "context_sha256",
      "rationale",
      "approved_at",
    ]) ||
    value.schema_version !== "1" ||
    value.lab_id !== expectedLabId ||
    typeof value.corpus_id !== "string" ||
    typeof value.assignment_id !== "string" ||
    typeof value.source_artifact_id !== "string" ||
    typeof value.analysis_mode !== "string" ||
    !ANALYSIS_MODES.has(value.analysis_mode as CourseAnalysisMode) ||
    typeof value.operation_id !== "string" ||
    !SAFE_ID.test(value.operation_id) ||
    typeof attestation !== "object" ||
    attestation === null ||
    Array.isArray(attestation) ||
    typeof value.specimen_sha256 !== "string" ||
    !SHA256.test(value.specimen_sha256) ||
    !Number.isSafeInteger(value.specimen_size_bytes) ||
    Number(value.specimen_size_bytes) <= 0 ||
    typeof value.specimen_media_type !== "string" ||
    typeof value.exact_source_artifact !== "boolean" ||
    typeof value.context_sha256 !== "string" ||
    !SHA256.test(value.context_sha256) ||
    typeof value.rationale !== "string" ||
    typeof value.approved_at !== "string" ||
    !canonicalTimestamp(value.approved_at)
  ) {
    throw new Error("Stored course-lab approval is malformed.");
  }
  const provider = attestation as Readonly<Record<string, unknown>>;
  if (
    !exactKeys(provider, [
      "attestation_id",
      "profile",
      "key_id",
      "issuer",
      "issued_at",
      "expires_at",
    ]) ||
    typeof provider.attestation_id !== "string" ||
    !ATTESTATION_ID.test(provider.attestation_id) ||
    provider.profile !== APPLE_NATIVE_ATTESTATION_PROFILE ||
    typeof provider.key_id !== "string" ||
    !ATTESTATION_KEY_ID.test(provider.key_id) ||
    typeof provider.issuer !== "string" ||
    provider.issuer.length === 0 ||
    provider.issuer.length > 128 ||
    !canonicalTimestamp(provider.issued_at) ||
    !canonicalTimestamp(provider.expires_at) ||
    provider.expires_at <= provider.issued_at
  ) {
    throw new Error("Stored course-lab provider attestation is malformed.");
  }
  if (
    !SAFE_ID.test(value.corpus_id) ||
    !SAFE_ID.test(value.assignment_id) ||
    !SAFE_ID.test(value.source_artifact_id) ||
    normalizeSpecimenMediaType(value.specimen_media_type) !== value.specimen_media_type ||
    normalizedRationale(value.rationale) !== value.rationale
  ) {
    throw new Error("Stored course-lab approval values are invalid.");
  }
  return value as unknown as CourseLabApprovalRecord;
}

function decodeSubmission(
  value: Readonly<Record<string, unknown>>,
  expectedLabId: string,
): CourseLabSubmissionRecord {
  if (
    !exactKeys(value, [
      "schema_version",
      "lab_id",
      "job_id",
      "operation_id",
      "provider_attestation_id",
      "specimen_artifact_id",
      "context_artifact_id",
      "submitted_at",
    ]) ||
    value.schema_version !== "1" ||
    value.lab_id !== expectedLabId ||
    typeof value.job_id !== "string" ||
    !JOB_ID.test(value.job_id) ||
    typeof value.operation_id !== "string" ||
    !SAFE_ID.test(value.operation_id) ||
    typeof value.provider_attestation_id !== "string" ||
    !ATTESTATION_ID.test(value.provider_attestation_id) ||
    typeof value.specimen_artifact_id !== "string" ||
    !ARTIFACT_ID.test(value.specimen_artifact_id) ||
    typeof value.context_artifact_id !== "string" ||
    !ARTIFACT_ID.test(value.context_artifact_id) ||
    !canonicalTimestamp(value.submitted_at)
  ) {
    throw new Error("Stored course-lab submission is malformed.");
  }
  return value as unknown as CourseLabSubmissionRecord;
}

function decodeCollection(
  value: Readonly<Record<string, unknown>>,
  expectedLabId: string,
): CourseLabCollection {
  if (
    !exactKeys(value, [
      "schema_version",
      "lab_id",
      "assignment_id",
      "evidence_artifact_id",
      "evidence_sha256",
      "execution_attestation_artifact_id",
      "provider_attestation_id",
      "collected_at",
    ]) ||
    value.schema_version !== "1" ||
    value.lab_id !== expectedLabId ||
    typeof value.assignment_id !== "string" ||
    !SAFE_ID.test(value.assignment_id) ||
    typeof value.evidence_artifact_id !== "string" ||
    !ARTIFACT_ID.test(value.evidence_artifact_id) ||
    typeof value.evidence_sha256 !== "string" ||
    !SHA256.test(value.evidence_sha256) ||
    typeof value.execution_attestation_artifact_id !== "string" ||
    !ARTIFACT_ID.test(value.execution_attestation_artifact_id) ||
    typeof value.provider_attestation_id !== "string" ||
    !ATTESTATION_ID.test(value.provider_attestation_id) ||
    !canonicalTimestamp(value.collected_at)
  ) {
    throw new Error("Stored course-lab collection is malformed.");
  }
  return value as unknown as CourseLabCollection;
}

export class CourseLabController {
  readonly #config: TemplarConfig;
  readonly #drone: CourseLabDroneClient;
  readonly #manifest: () => Promise<CourseCorpusManifest>;
  readonly #root: string;

  constructor(
    config: TemplarConfig,
    drone: CourseLabDroneClient,
    options: { readonly manifest?: () => Promise<CourseCorpusManifest> } = {},
  ) {
    this.#config = config;
    this.#drone = drone;
    this.#manifest = options.manifest ?? (() => loadCourseCorpusManifest());
    this.#root = path.join(config.templarHome, "course-lab");
  }

  async initialize(): Promise<void> {
    await mkdir(this.#root, { recursive: true, mode: 0o700 });
    await privateDirectory(this.#root);
  }

  async submit(options: {
    readonly sourceArtifactId: string;
    readonly specimenFile: string;
    readonly specimenMediaType: string;
    readonly approvedProviderAttestationId: string;
    readonly rationale: string;
  }): Promise<CourseLabStatus> {
    await this.initialize();
    if (!this.#config.droneEnabled || this.#config.droneCourseLabOperationId === undefined) {
      throw conflict("Drone course-lab execution is not explicitly configured.");
    }
    const approvedId = approvedAttestationId(options.approvedProviderAttestationId);
    const rationale = normalizedRationale(options.rationale);
    const specimenMediaType = normalizeSpecimenMediaType(options.specimenMediaType);
    const [manifest, specimenBytes, providers, operations] = await Promise.all([
      this.#manifest(),
      boundedFile(options.specimenFile, this.#config.maxCourseLabSpecimenBytes),
      this.#drone.providers(),
      this.#drone.operations(),
    ]);
    const { artifact: source, assignment } = findSource(manifest, options.sourceArtifactId);
    const specimenDigest = sha256(specimenBytes);
    const exactSourceArtifact =
      source.sha256 === specimenDigest && source.byte_length === specimenBytes.byteLength;
    const providerAttestation = assertProvider(providers, approvedId);
    const context: CourseLabContext = {
      schema_version: "1",
      profile: "templar_course_assignment_lab_v1",
      corpus_id: manifest.corpus_id,
      assignment_id: assignment.assignment_id,
      source_artifact_id: source.artifact_id,
      analysis_mode: assignment.analysis_mode,
      requirement_ids: assignment.requirement_ids,
      required_check_ids: courseChecksForAnalysisMode(assignment.analysis_mode),
      assignment_artifact_ids: assignment.artifact_ids,
      specimen: {
        sha256: specimenDigest,
        size_bytes: specimenBytes.byteLength,
        media_type: specimenMediaType,
        exact_source_artifact: exactSourceArtifact,
      },
    };
    const contextBytes = Buffer.from(`${JSON.stringify(context)}\n`, "utf8");
    const operation = assertOperation(
      operations.find(
        (candidate) => candidate.operation_id === this.#config.droneCourseLabOperationId,
      ),
      specimenMediaType,
      specimenBytes.byteLength,
      contextBytes.byteLength,
    );
    const id = `lab_${randomUUID().replaceAll("-", "")}`;
    const directory = path.join(this.#root, id);
    await mkdir(directory, { mode: 0o700 });
    await privateDirectory(directory);
    const approval: CourseLabApprovalRecord = {
      schema_version: "1",
      lab_id: id,
      corpus_id: manifest.corpus_id,
      assignment_id: assignment.assignment_id,
      source_artifact_id: source.artifact_id,
      analysis_mode: assignment.analysis_mode,
      operation_id: operation.operation_id,
      provider_attestation: providerAttestation,
      specimen_sha256: specimenDigest,
      specimen_size_bytes: specimenBytes.byteLength,
      specimen_media_type: specimenMediaType,
      exact_source_artifact: exactSourceArtifact,
      context_sha256: sha256(contextBytes),
      rationale,
      approved_at: new Date().toISOString(),
    };
    await writeFile(path.join(directory, "approval.json"), `${JSON.stringify(approval)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });

    const [specimenArtifact, contextArtifact] = await Promise.all([
      this.#drone.stageArtifact(specimenBytes, specimenMediaType),
      this.#drone.stageArtifact(contextBytes, COURSE_LAB_CONTEXT_MEDIA_TYPE),
    ]);
    const job = await this.#drone.submitJob({
      schema_version: "1",
      operation_id: operation.operation_id,
      provider_attestation_id: approvedId,
      inputs: {
        specimen: specimenArtifact.artifact_id,
        context: contextArtifact.artifact_id,
      },
    });
    if (
      job.provider_id !== "apple_native" ||
      job.provider_attestation_id !== approvedId ||
      job.operation_id !== operation.operation_id
    ) {
      throw unavailable("Drone admitted the course lab under an unrelated attestation.");
    }
    const submission: CourseLabSubmissionRecord = {
      schema_version: "1",
      lab_id: id,
      job_id: job.job_id,
      operation_id: operation.operation_id,
      provider_attestation_id: approvedId,
      specimen_artifact_id: specimenArtifact.artifact_id,
      context_artifact_id: contextArtifact.artifact_id,
      submitted_at: job.submitted_at,
    };
    await writeFile(path.join(directory, "submission.json"), `${JSON.stringify(submission)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
    return { approval, submission, job };
  }

  async status(value: string): Promise<CourseLabStatus> {
    await this.initialize();
    const id = labId(value);
    const directory = path.join(this.#root, id);
    await privateDirectory(directory).catch((cause) => {
      throw new TemplarError({
        code: "NOT_FOUND",
        message: "Course lab was not found.",
        status: 404,
        cause,
      });
    });
    let approval: CourseLabApprovalRecord;
    let submission: CourseLabSubmissionRecord;
    try {
      [approval, submission] = await Promise.all([
        recordFile(path.join(directory, "approval.json")).then((record) =>
          decodeApproval(record, id),
        ),
        recordFile(path.join(directory, "submission.json")).then((record) =>
          decodeSubmission(record, id),
        ),
      ]);
    } catch (cause) {
      throw unavailable("Course-lab custody records are unavailable.", cause);
    }
    const job = await this.#drone.job(submission.job_id);
    if (
      job.operation_id !== submission.operation_id ||
      job.provider_id !== "apple_native" ||
      job.provider_attestation_id !== submission.provider_attestation_id ||
      job.provider_attestation_id !== approval.provider_attestation.attestation_id ||
      job.inputs.specimen !== submission.specimen_artifact_id ||
      job.inputs.context !== submission.context_artifact_id
    ) {
      throw unavailable("Drone returned an unrelated course-lab job.");
    }
    return { approval, submission, job };
  }

  async collect(value: string, destination: string): Promise<CourseLabCollection> {
    const current = await this.status(value);
    if (
      current.job.status !== "succeeded" ||
      current.job.execution_attestation_artifact_id === undefined
    ) {
      throw conflict("Course-lab evidence can be collected only from an attested successful job.");
    }
    const outputs = current.job.outputs.filter((output) => output.name === "evidence");
    if (
      outputs.length !== 1 ||
      current.job.outputs.length !== 1 ||
      outputs[0]?.media_type !== COURSE_LAB_EVIDENCE_MEDIA_TYPE
    ) {
      throw unavailable("Drone course-lab output does not match the declared evidence contract.");
    }
    const evidenceOutput = outputs[0];
    const [evidenceDownload, executionDownload, manifest] = await Promise.all([
      this.#drone.artifactContent(evidenceOutput.artifact_id),
      this.#drone.artifactContent(current.job.execution_attestation_artifact_id),
      this.#manifest(),
    ]);
    if (
      evidenceDownload.mediaType !== COURSE_LAB_EVIDENCE_MEDIA_TYPE ||
      executionDownload.mediaType !== DRONE_EXECUTION_ATTESTATION_MEDIA_TYPE
    ) {
      throw unavailable("Drone returned an unexpected course-lab evidence media type.");
    }
    let parsedEvidence: unknown;
    let parsedExecution: unknown;
    try {
      parsedEvidence = JSON.parse(Buffer.from(evidenceDownload.bytes).toString("utf8")) as unknown;
      parsedExecution = JSON.parse(
        Buffer.from(executionDownload.bytes).toString("utf8"),
      ) as unknown;
    } catch (cause) {
      throw unavailable("Drone course-lab evidence is not JSON.", cause);
    }
    const assignment = manifest.assignments.find(
      (candidate) => candidate.assignment_id === current.approval.assignment_id,
    );
    if (assignment === undefined) throw unavailable("Course-lab assignment left the manifest.");
    const evidence = validateAssignmentEvidence(parsedEvidence, assignment);
    const execution = decodeDroneExecutionAttestation(parsedExecution);
    if (execution.provider_attestation_id !== current.submission.provider_attestation_id) {
      throw unavailable("Execution evidence does not match the approved provider attestation.");
    }
    const normalizedEvidence = Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
    const normalizedExecution = Buffer.from(`${JSON.stringify(execution, null, 2)}\n`, "utf8");
    const collection: CourseLabCollection = {
      schema_version: "1",
      lab_id: current.approval.lab_id,
      assignment_id: assignment.assignment_id,
      evidence_artifact_id: evidenceOutput.artifact_id,
      evidence_sha256: sha256(normalizedEvidence),
      execution_attestation_artifact_id: current.job.execution_attestation_artifact_id,
      provider_attestation_id: current.submission.provider_attestation_id,
      collected_at: new Date().toISOString(),
    };
    const directory = path.join(this.#root, current.approval.lab_id);
    const targetCollection = path.join(directory, "collection");
    const temporary = path.join(directory, `.collection-${randomUUID()}`);
    await mkdir(temporary, { mode: 0o700 });
    try {
      await Promise.all([
        writeFile(path.join(temporary, "evidence.json"), normalizedEvidence, {
          mode: 0o600,
          flag: "wx",
        }),
        writeFile(path.join(temporary, "execution-attestation.json"), normalizedExecution, {
          mode: 0o600,
          flag: "wx",
        }),
        writeFile(path.join(temporary, "collection.json"), `${JSON.stringify(collection)}\n`, {
          encoding: "utf8",
          mode: 0o600,
          flag: "wx",
        }),
      ]);
      await rename(temporary, targetCollection);
    } catch (cause) {
      await rm(temporary, { recursive: true, force: true }).catch(() => undefined);
      const existing = await lstat(targetCollection).catch(() => undefined);
      if (existing === undefined || !existing.isDirectory() || existing.isSymbolicLink()) {
        throw unavailable("Unable to preserve course-lab evidence custody.", cause);
      }
    }
    const preserved = await readFile(path.join(targetCollection, "evidence.json"));
    if (sha256(preserved) !== collection.evidence_sha256) {
      throw unavailable("Preserved course-lab evidence no longer matches its custody record.");
    }
    await writeFile(path.resolve(destination), preserved, { mode: 0o600, flag: "wx" });
    return collection;
  }

  async exerciseSnapshot(value: string): Promise<ExerciseSnapshot> {
    const current = await this.status(value);
    if (
      current.job.status !== "succeeded" ||
      current.job.execution_attestation_artifact_id === undefined
    ) {
      throw conflict("Course-lab evidence must be collected before it can become an exercise.");
    }
    const evidenceOutput = current.job.outputs.find((output) => output.name === "evidence");
    if (evidenceOutput === undefined || current.job.outputs.length !== 1) {
      throw unavailable("Course-lab evidence output is unavailable.");
    }
    const directory = path.join(this.#root, current.approval.lab_id, "collection");
    await privateDirectory(directory).catch((cause) => {
      throw conflict(
        "Course-lab evidence must be collected before it can become an exercise.",
        cause,
      );
    });
    let evidenceBytes: Buffer;
    let executionBytes: Buffer;
    let collection: CourseLabCollection;
    let manifest: CourseCorpusManifest;
    try {
      [evidenceBytes, executionBytes, collection, manifest] = await Promise.all([
        boundedFile(path.join(directory, "evidence.json"), 2 * 1024 * 1024),
        boundedFile(path.join(directory, "execution-attestation.json"), MAX_RECORD_BYTES),
        recordFile(path.join(directory, "collection.json")).then((record) =>
          decodeCollection(record, current.approval.lab_id),
        ),
        this.#manifest(),
      ]);
    } catch (cause) {
      throw unavailable("Course-lab collection custody is unavailable.", cause);
    }
    if (
      collection.assignment_id !== current.approval.assignment_id ||
      collection.evidence_artifact_id !== evidenceOutput.artifact_id ||
      collection.execution_attestation_artifact_id !==
        current.job.execution_attestation_artifact_id ||
      collection.provider_attestation_id !== current.submission.provider_attestation_id ||
      sha256(evidenceBytes) !== collection.evidence_sha256
    ) {
      throw unavailable("Course-lab collection no longer matches its admitted job.");
    }
    const assignment = manifest.assignments.find(
      (candidate) => candidate.assignment_id === current.approval.assignment_id,
    );
    if (assignment === undefined) throw unavailable("Course-lab assignment left the manifest.");
    let evidenceValue: unknown;
    let executionValue: unknown;
    try {
      evidenceValue = JSON.parse(evidenceBytes.toString("utf8")) as unknown;
      executionValue = JSON.parse(executionBytes.toString("utf8")) as unknown;
    } catch (cause) {
      throw unavailable("Collected course-lab evidence is not JSON.", cause);
    }
    const evidence = validateAssignmentEvidence(evidenceValue, assignment)[0];
    if (evidence === undefined) throw unavailable("Collected course-lab evidence is empty.");
    const execution = decodeDroneExecutionAttestation(executionValue);
    if (
      execution.provider_attestation_id !== collection.provider_attestation_id ||
      execution.image_reference.length === 0
    ) {
      throw unavailable("Collected execution evidence left the approved provider boundary.");
    }
    const executionObservationId = `${assignment.assignment_id}.observation.execution-provenance`;
    if (
      evidence.observations.some(
        (observation) => observation.observation_id === executionObservationId,
      )
    ) {
      throw unavailable("Course-lab evidence collides with the reserved execution provenance ID.");
    }
    return decodeExerciseSnapshot({
      schema_version: "1",
      exercise_id: `course-assignment.${manifest.corpus_id}.${assignment.assignment_id}`,
      title: `${assignment.title} — attested passive evidence`,
      artifact: {
        digest: `sha256:${collection.evidence_sha256}`,
        size: evidenceBytes.byteLength,
        media_type: COURSE_ASSIGNMENT_EVIDENCE_MEDIA_TYPE,
      },
      analyzer: {
        analyzer_id: COURSE_LAB_ANALYZER_ID,
        version: COURSE_LAB_ANALYZER_VERSION,
      },
      questions: evidence.questions,
      observations: [
        ...evidence.observations.map((observation) => ({
          observation_id: observation.observation_id,
          kind: observation.kind,
          text: `Provenance artifact IDs: ${observation.artifact_ids.join(", ")}\n\n${observation.text}`,
          required: observation.required,
        })),
        {
          observation_id: executionObservationId,
          kind: "execution_attestation",
          text: `Provider attestation ${collection.provider_attestation_id}; execution artifact ${collection.execution_attestation_artifact_id}; image ${execution.image_reference}; backend ${execution.backend}; isolation ${execution.isolation}; guest ${execution.guest_os}; network ${execution.network_mode}; ephemeral VM ${String(execution.ephemeral_vm)}; read-only root ${String(execution.read_only_root)}; read-only input disk ${String(execution.input_disk_read_only)}; bounded output disk ${String(execution.output_disk_bounded)}; host directory sharing ${String(execution.host_directory_sharing)}; socket sharing ${String(execution.socket_sharing)}; nested virtualization ${String(execution.nested_virtualization)}; non-root ${String(execution.non_root_required)}; no-new-privileges ${String(execution.no_new_privileges)}; capabilities ${execution.capabilities}; source specimen SHA-256 ${current.approval.specimen_sha256}.`,
          required: true,
        },
      ],
      available_checks: evidence.check_ids,
    });
  }
}
