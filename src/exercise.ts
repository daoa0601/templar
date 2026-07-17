import { Schema, SchemaParser } from "effect";

import { invalidInput } from "./errors.js";

export const MAX_EXERCISE_QUESTIONS = 32;
export const MAX_EXERCISE_OBSERVATIONS = 24;
export const MAX_EXERCISE_PROMPT_TEXT = 4_000;
export const MAX_EXERCISE_OBSERVATION_TEXT = 100_000;

const ExerciseQuestionSchema = Schema.Struct({
  question_id: Schema.String,
  prompt: Schema.String,
});

const ExerciseObservationSchema = Schema.Struct({
  observation_id: Schema.String,
  kind: Schema.String,
  text: Schema.String,
  required: Schema.Boolean,
});

const ExerciseSnapshotSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  exercise_id: Schema.String,
  title: Schema.String,
  artifact: Schema.Struct({
    digest: Schema.String,
    size: Schema.Number,
    media_type: Schema.Literal("application/vnd.microsoft.portable-executable"),
  }),
  analyzer: Schema.Struct({
    analyzer_id: Schema.String,
    version: Schema.String,
  }),
  questions: Schema.Array(ExerciseQuestionSchema),
  observations: Schema.Array(ExerciseObservationSchema),
  available_checks: Schema.Array(Schema.String),
});

const decodeSnapshotShape = SchemaParser.decodeUnknownSync(ExerciseSnapshotSchema, {
  errors: "all",
  onExcessProperty: "error",
});

const SAFE_ID = /^[a-z][a-z0-9_.-]{0,127}$/u;
const DIGEST = /^sha256:[a-f0-9]{64}$/u;

export interface ExerciseQuestion {
  readonly question_id: string;
  readonly prompt: string;
}

export interface ExerciseObservation {
  readonly observation_id: string;
  readonly kind: string;
  readonly text: string;
  readonly required: boolean;
}

export interface ExerciseSnapshot {
  readonly schema_version: "1";
  readonly exercise_id: string;
  readonly title: string;
  readonly artifact: {
    readonly digest: string;
    readonly size: number;
    readonly media_type: "application/vnd.microsoft.portable-executable";
  };
  readonly analyzer: {
    readonly analyzer_id: string;
    readonly version: string;
  };
  readonly questions: ReadonlyArray<ExerciseQuestion>;
  readonly observations: ReadonlyArray<ExerciseObservation>;
  readonly available_checks: ReadonlyArray<string>;
}

export interface ExerciseEvaluationContext {
  readonly schema_version: "1";
  readonly known_question_ids: ReadonlyArray<string>;
  readonly required_question_ids: ReadonlyArray<string>;
  readonly known_observation_ids: ReadonlyArray<string>;
  readonly required_observation_ids: ReadonlyArray<string>;
  readonly available_checks: ReadonlyArray<string>;
}

function text(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maximum) {
    throw invalidInput(`${label} must contain 1-${maximum} characters.`);
  }
  if (normalized.includes(String.fromCharCode(0))) {
    throw invalidInput(`${label} contains a null byte.`);
  }
  return normalized;
}

function id(value: string, label: string): string {
  const normalized = text(value, label, 128);
  if (!SAFE_ID.test(normalized)) throw invalidInput(`${label} is invalid.`);
  return normalized;
}

function uniqueIds(values: ReadonlyArray<string>, label: string): void {
  if (new Set(values).size !== values.length) throw invalidInput(`${label} contains duplicates.`);
}

export function decodeExerciseSnapshot(value: unknown): ExerciseSnapshot {
  let input: typeof ExerciseSnapshotSchema.Type;
  try {
    input = decodeSnapshotShape(value);
  } catch (cause) {
    throw invalidInput("ExerciseSnapshot v1 does not match the strict schema.", cause);
  }
  if (input.questions.length === 0 || input.questions.length > MAX_EXERCISE_QUESTIONS) {
    throw invalidInput(`questions must contain 1-${MAX_EXERCISE_QUESTIONS} entries.`);
  }
  if (input.observations.length === 0 || input.observations.length > MAX_EXERCISE_OBSERVATIONS) {
    throw invalidInput(`observations must contain 1-${MAX_EXERCISE_OBSERVATIONS} entries.`);
  }
  if (!DIGEST.test(input.artifact.digest)) throw invalidInput("artifact.digest is invalid.");
  if (!Number.isSafeInteger(input.artifact.size) || input.artifact.size <= 0) {
    throw invalidInput("artifact.size must be a positive integer.");
  }

  const questions = input.questions.map((question, index) => ({
    question_id: id(question.question_id, `questions[${index}].question_id`),
    prompt: text(question.prompt, `questions[${index}].prompt`, MAX_EXERCISE_PROMPT_TEXT),
  }));
  uniqueIds(
    questions.map((question) => question.question_id),
    "question IDs",
  );

  const observations = input.observations.map((observation, index) => ({
    observation_id: id(observation.observation_id, `observations[${index}].observation_id`),
    kind: id(observation.kind, `observations[${index}].kind`),
    text: text(observation.text, `observations[${index}].text`, MAX_EXERCISE_OBSERVATION_TEXT),
    required: observation.required,
  }));
  uniqueIds(
    observations.map((observation) => observation.observation_id),
    "observation IDs",
  );

  const checks = input.available_checks.map((check, index) =>
    id(check, `available_checks[${index}]`),
  );
  if (checks.length === 0) throw invalidInput("available_checks must not be empty.");
  uniqueIds(checks, "available_checks");

  return {
    schema_version: "1",
    exercise_id: id(input.exercise_id, "exercise_id"),
    title: text(input.title, "title", 256),
    artifact: {
      digest: input.artifact.digest,
      size: input.artifact.size,
      media_type: "application/vnd.microsoft.portable-executable",
    },
    analyzer: {
      analyzer_id: id(input.analyzer.analyzer_id, "analyzer.analyzer_id"),
      version: text(input.analyzer.version, "analyzer.version", 256),
    },
    questions,
    observations,
    available_checks: checks,
  };
}

export function exerciseEvaluationContext(snapshot: ExerciseSnapshot): ExerciseEvaluationContext {
  return {
    schema_version: "1",
    known_question_ids: snapshot.questions.map((question) => question.question_id),
    required_question_ids: snapshot.questions.map((question) => question.question_id),
    known_observation_ids: snapshot.observations.map((observation) => observation.observation_id),
    required_observation_ids: snapshot.observations
      .filter((observation) => observation.required)
      .map((observation) => observation.observation_id),
    available_checks: snapshot.available_checks,
  };
}
