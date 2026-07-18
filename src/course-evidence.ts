import { createHash } from "node:crypto";

import { Schema, SchemaParser } from "effect";

import type {
  CourseAnalysisMode,
  CourseCorpusInventory,
  CourseCorpusManifest,
} from "./course-corpus.js";
import type { ExerciseObservation, ExerciseQuestion, ExerciseSnapshot } from "./exercise.js";
import { invalidInput } from "./errors.js";

export const COURSE_ANALYZER_ID = "templar_course_corpus";
export const COURSE_ANALYZER_VERSION = "1.1.0";
const MAX_PORTABLE_OBSERVATION_TEXT = 1_400;

const CHECKS_BY_MODE: Readonly<Record<CourseAnalysisMode, ReadonlyArray<string>>> = {
  windows_forensics: [
    "registry_hive_parse",
    "evtx_parse",
    "prefetch_parse",
    "lnk_parse",
    "timeline_normalization",
  ],
  native_static: ["pe_headers", "targeted_disassembly", "section_hex_dump"],
  native_dynamic_semantics: ["pe_static_decode", "headless_decompilation", "manual_semantic_trace"],
  dotnet_reverse_engineering: ["dotnet_metadata", "resource_unpack", "cryptographic_reproduction"],
  dotnet_batch: [
    "bounded_archive_stream",
    "dotnet_bundle_parse",
    "cryptographic_reproduction",
    "result_count",
  ],
};

export function courseChecksForAnalysisMode(mode: CourseAnalysisMode): ReadonlyArray<string> {
  return CHECKS_BY_MODE[mode];
}

const SAFE_ID = /^[a-z][a-z0-9_.-]{0,127}$/u;

const CourseAssignmentEvidenceSchema = Schema.Array(
  Schema.Struct({
    assignment_id: Schema.String,
    questions: Schema.Array(Schema.Struct({ question_id: Schema.String, prompt: Schema.String })),
    observations: Schema.Array(
      Schema.Struct({
        observation_id: Schema.String,
        kind: Schema.String,
        text: Schema.String,
        artifact_ids: Schema.Array(Schema.String),
        required: Schema.Boolean,
      }),
    ),
    check_ids: Schema.Array(Schema.String),
  }),
);

const decodeEvidenceShape = SchemaParser.decodeUnknownSync(CourseAssignmentEvidenceSchema, {
  errors: "all",
  onExcessProperty: "error",
});

export interface CourseEvidenceObservation {
  readonly observation_id: string;
  readonly kind: string;
  readonly text: string;
  readonly artifact_ids: ReadonlyArray<string>;
  readonly required: boolean;
}

export interface CourseAssignmentEvidence {
  readonly assignment_id: string;
  readonly questions: ReadonlyArray<ExerciseQuestion>;
  readonly observations: ReadonlyArray<CourseEvidenceObservation>;
  readonly check_ids: ReadonlyArray<string>;
}

export function decodeCourseAssignmentEvidence(
  value: unknown,
): ReadonlyArray<CourseAssignmentEvidence> {
  try {
    return decodeEvidenceShape(value);
  } catch (cause) {
    throw invalidInput("Course assignment evidence does not match the strict schema.", cause);
  }
}

function unique(values: ReadonlyArray<string>, label: string): void {
  if (new Set(values).size !== values.length) throw invalidInput(`${label} contains duplicates.`);
}

function sameMembers(left: ReadonlyArray<string>, right: ReadonlyArray<string>): boolean {
  return (
    left.length === right.length &&
    [...left].sort().every((value, index) => value === [...right].sort()[index])
  );
}

function boundedText(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > maximum ||
    normalized.includes(String.fromCharCode(0))
  ) {
    throw invalidInput(`${label} is invalid.`);
  }
  return normalized;
}

function id(value: string, label: string): string {
  const normalized = boundedText(value, label, 128);
  if (!SAFE_ID.test(normalized)) throw invalidInput(`${label} is invalid.`);
  return normalized;
}

/** Stable identity for the metadata-only corpus contract; it never includes local host paths. */
export function courseCorpusIdentity(manifest: CourseCorpusManifest): {
  readonly digest: string;
  readonly size: number;
} {
  const identity = {
    schema_version: manifest.schema_version,
    corpus_id: manifest.corpus_id,
    artifacts: manifest.artifacts.map((artifact) => ({
      artifact_id: artifact.artifact_id,
      byte_length: artifact.byte_length,
      sha256: artifact.sha256,
    })),
  };
  return {
    digest: `sha256:${createHash("sha256").update(JSON.stringify(identity)).digest("hex")}`,
    size: manifest.artifacts.reduce((sum, artifact) => sum + artifact.byte_length, 0),
  };
}

function splitLongObservationLine(line: string): ReadonlyArray<string> {
  if (line.length <= MAX_PORTABLE_OBSERVATION_TEXT) return [line];
  const parts: string[] = [];
  let remaining = line;
  while (remaining.length > MAX_PORTABLE_OBSERVATION_TEXT) {
    const preferred = remaining.lastIndexOf(" ", MAX_PORTABLE_OBSERVATION_TEXT);
    const splitAt =
      preferred >= Math.floor(MAX_PORTABLE_OBSERVATION_TEXT * 0.75)
        ? preferred
        : MAX_PORTABLE_OBSERVATION_TEXT;
    parts.push(remaining.slice(0, splitAt).trimEnd());
    remaining = remaining.slice(splitAt).trimStart();
  }
  if (remaining.length > 0) parts.push(remaining);
  return parts;
}

function portableObservationText(value: string, label: string): ReadonlyArray<string> {
  const normalized = boundedText(value, label, 96_000);
  if (normalized.length <= MAX_PORTABLE_OBSERVATION_TEXT) return [normalized];
  const chunks: string[] = [];
  let current = "";
  for (const unit of normalized.split("\n").flatMap(splitLongObservationLine)) {
    const next = current.length === 0 ? unit : `${current}\n${unit}`;
    if (next.length <= MAX_PORTABLE_OBSERVATION_TEXT) {
      current = next;
      continue;
    }
    if (current.length > 0) chunks.push(current);
    current = unit;
  }
  if (current.length > 0) chunks.push(current);
  if (chunks.length === 0) throw invalidInput(`${label} could not be segmented.`);
  return chunks;
}

function validatedObservations(
  input: CourseEvidenceObservation,
  assignmentId: string,
  artifactIds: ReadonlySet<string>,
  index: number,
): ReadonlyArray<ExerciseObservation> {
  const observationId = id(input.observation_id, `observations[${index}].observation_id`);
  if (!observationId.startsWith(`${assignmentId}.observation.`)) {
    throw invalidInput(`Observation ${observationId} is not namespaced to ${assignmentId}.`);
  }
  const sources = input.artifact_ids.map((source, sourceIndex) =>
    id(source, `observations[${index}].artifact_ids[${sourceIndex}]`),
  );
  if (sources.length === 0) throw invalidInput(`Observation ${observationId} has no provenance.`);
  unique(sources, `Observation ${observationId} artifact IDs`);
  for (const source of sources) {
    if (!artifactIds.has(source)) {
      throw invalidInput(
        `Observation ${observationId} cites unknown assignment artifact ${source}.`,
      );
    }
  }
  const kind = id(input.kind, `observations[${index}].kind`);
  const chunks = portableObservationText(input.text, `observations[${index}].text`);
  return chunks.map((evidence, chunkIndex) => {
    const part = `.part-${String(chunkIndex + 1).padStart(2, "0")}`;
    const segmentedId = chunks.length === 1 ? observationId : `${observationId}${part}`;
    if (!SAFE_ID.test(segmentedId) || segmentedId.length > 128) {
      throw invalidInput(`Observation ${observationId} is too long to segment safely.`);
    }
    return {
      observation_id: segmentedId,
      kind,
      text: `Provenance artifact IDs: ${sources.join(", ")}${
        chunks.length === 1
          ? ""
          : `\nPortable segment ${chunkIndex + 1} of ${chunks.length} from ${observationId}.`
      }\n\n${evidence}`,
      required: input.required,
    };
  });
}

/**
 * Compose analyzer outputs into the generic immutable exercise snapshot consumed by Templar.
 * The composition contract covers every declared requirement exactly once and carries evidence,
 * never course answers or specimen bytes.
 */
export function buildCourseExerciseSnapshot(options: {
  readonly manifest: CourseCorpusManifest;
  readonly inventory: CourseCorpusInventory;
  readonly assignments: unknown;
}): ExerciseSnapshot {
  const { manifest, inventory } = options;
  const evidenceAssignments = decodeCourseAssignmentEvidence(options.assignments);
  if (!inventory.complete || inventory.corpus_id !== manifest.corpus_id) {
    throw invalidInput("A complete, matching course inventory is required.");
  }
  if (
    inventory.assignment_count !== manifest.assignments.length ||
    inventory.requirement_count !== manifest.requirement_count ||
    inventory.verified_artifact_count !== manifest.artifacts.length ||
    inventory.artifacts.length !== manifest.artifacts.length ||
    !sameMembers(
      inventory.artifacts
        .filter((artifact) => artifact.status === "verified")
        .map((artifact) => artifact.artifact_id),
      manifest.artifacts.map((artifact) => artifact.artifact_id),
    )
  ) {
    throw invalidInput("The course inventory does not prove every manifest artifact.");
  }
  if (evidenceAssignments.length !== manifest.assignments.length) {
    throw invalidInput("Course evidence must cover every assignment exactly once.");
  }
  unique(
    evidenceAssignments.map((assignment) => assignment.assignment_id),
    "Course evidence assignment IDs",
  );

  const questions: ExerciseQuestion[] = [];
  const observations: ExerciseObservation[] = [];
  const checks = new Set<string>();
  for (const assignment of manifest.assignments) {
    const supplied = evidenceAssignments.find(
      (candidate) => candidate.assignment_id === assignment.assignment_id,
    );
    if (supplied === undefined) {
      throw invalidInput(`Course evidence is missing assignment ${assignment.assignment_id}.`);
    }
    const questionIds = supplied.questions.map((question) => question.question_id);
    unique(questionIds, `${assignment.assignment_id} question IDs`);
    if (!sameMembers(questionIds, assignment.requirement_ids)) {
      throw invalidInput(`${assignment.assignment_id} questions do not match its requirements.`);
    }
    for (const question of supplied.questions) {
      questions.push({
        question_id: id(question.question_id, "question_id"),
        prompt: boundedText(question.prompt, `${question.question_id}.prompt`, 4_000),
      });
    }

    if (supplied.observations.length === 0) {
      throw invalidInput(`${assignment.assignment_id} has no analyzer observations.`);
    }
    const ownedArtifacts = new Set(assignment.artifact_ids);
    observations.push(
      ...supplied.observations.flatMap((observation, index) =>
        validatedObservations(observation, assignment.assignment_id, ownedArtifacts, index),
      ),
    );
    const allowedChecks = CHECKS_BY_MODE[assignment.analysis_mode];
    unique(supplied.check_ids, `${assignment.assignment_id} check IDs`);
    if (!sameMembers(supplied.check_ids, allowedChecks)) {
      throw invalidInput(
        `${assignment.assignment_id} must provide its complete passive check set.`,
      );
    }
    for (const check of supplied.check_ids) checks.add(check);
  }
  unique(
    observations.map((observation) => observation.observation_id),
    "Course observation IDs",
  );
  const corpus = courseCorpusIdentity(manifest);
  return {
    schema_version: "1",
    exercise_id: `course.${manifest.corpus_id}`,
    title: manifest.title,
    artifact: {
      ...corpus,
      media_type: "application/vnd.templar.course-corpus+json",
    },
    analyzer: {
      analyzer_id: COURSE_ANALYZER_ID,
      version: COURSE_ANALYZER_VERSION,
    },
    questions,
    observations,
    available_checks: [...checks],
  };
}

/** Reject a hand-crafted course marker that does not match the versioned corpus contract. */
export function assertCourseExerciseSnapshot(
  snapshot: ExerciseSnapshot,
  manifest: CourseCorpusManifest,
): void {
  if (
    snapshot.artifact.media_type !== "application/vnd.templar.course-corpus+json" ||
    snapshot.analyzer.analyzer_id !== COURSE_ANALYZER_ID ||
    snapshot.analyzer.version !== COURSE_ANALYZER_VERSION ||
    snapshot.exercise_id !== `course.${manifest.corpus_id}`
  ) {
    throw invalidInput("The exercise is not a recognized course-corpus snapshot.");
  }
  const expectedIdentity = courseCorpusIdentity(manifest);
  if (
    snapshot.artifact.digest !== expectedIdentity.digest ||
    snapshot.artifact.size !== expectedIdentity.size
  ) {
    throw invalidInput("The course exercise identity does not match the corpus manifest.");
  }
  const expectedQuestions = manifest.assignments.flatMap(
    (assignment) => assignment.requirement_ids,
  );
  if (
    !sameMembers(
      snapshot.questions.map(({ question_id }) => question_id),
      expectedQuestions,
    )
  ) {
    throw invalidInput("The course exercise does not cover all corpus requirements exactly once.");
  }
  for (const assignment of manifest.assignments) {
    if (
      !snapshot.observations.some(({ observation_id }) =>
        observation_id.startsWith(`${assignment.assignment_id}.observation.`),
      )
    ) {
      throw invalidInput(`The course exercise has no evidence for ${assignment.assignment_id}.`);
    }
    for (const requiredCheck of CHECKS_BY_MODE[assignment.analysis_mode]) {
      if (!snapshot.available_checks.includes(requiredCheck)) {
        throw invalidInput(`The course exercise is missing check ${requiredCheck}.`);
      }
    }
  }
}

export function isCourseExerciseSnapshot(snapshot: ExerciseSnapshot): boolean {
  return snapshot.artifact.media_type === "application/vnd.templar.course-corpus+json";
}
