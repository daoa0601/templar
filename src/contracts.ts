import { Schema, SchemaParser } from "effect";

import { invalidInput } from "./errors.js";

export const MAX_INCIDENT_TEXT = 4_000;
export const MAX_OBSERVATIONS = 32;
export const MAX_OBSERVATION_TEXT = 256;

const ObservationInputSchema = Schema.Struct({
  observation_id: Schema.String,
  kind: Schema.String,
  value: Schema.Unknown,
  unit: Schema.optionalKey(Schema.String),
});

const IncidentInputSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  request: Schema.String,
  observations: Schema.optionalKey(Schema.Array(ObservationInputSchema)),
  ticket_ref: Schema.optionalKey(Schema.String),
  reported_priority: Schema.optionalKey(Schema.String),
  pcap_artifact_id: Schema.optionalKey(Schema.String),
});

const PcapSecurityTriageInputSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  pcap_artifact_id: Schema.String,
});

const ExerciseSolveInputSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  exercise_snapshot_id: Schema.String,
});

const decodeIncidentShape = SchemaParser.decodeUnknownSync(IncidentInputSchema, {
  errors: "all",
  onExcessProperty: "error",
});

const decodePcapSecurityTriageShape = SchemaParser.decodeUnknownSync(
  PcapSecurityTriageInputSchema,
  {
    errors: "all",
    onExcessProperty: "error",
  },
);

const decodeExerciseSolveShape = SchemaParser.decodeUnknownSync(ExerciseSolveInputSchema, {
  errors: "all",
  onExcessProperty: "error",
});

export interface StructuredObservation {
  readonly observation_id: string;
  readonly kind: string;
  readonly value: string | number | boolean;
  readonly unit?: string;
}

export interface IncidentInput {
  readonly schema_version: "1";
  readonly request: string;
  readonly observations: ReadonlyArray<StructuredObservation>;
  readonly ticket_ref?: string;
  readonly reported_priority?: string;
  readonly pcap_artifact_id?: string;
}

export interface PcapSecurityTriageInput {
  readonly schema_version: "1";
  readonly pcap_artifact_id: string;
}

export interface ExerciseSolveInput {
  readonly schema_version: "1";
  readonly exercise_snapshot_id: string;
}

const SAFE_ID = /^[a-z][a-z0-9_.-]{0,63}$/u;
const SAFE_KIND = /^[a-z][a-z0-9_.-]{0,63}$/u;
const TICKET_REF = /^[A-Z][A-Z0-9]{1,9}-[1-9][0-9]{0,9}$/u;
const ARTIFACT_ID = /^pcap_sha256_[a-f0-9]{64}$/u;
const EXERCISE_SNAPSHOT_ID = /^exercise_sha256_[a-f0-9]{64}$/u;
const PRIORITY = /^(?:lowest|low|medium|high|highest|p[1-5])$/iu;
const URL = /\b(?:https?|file|ftp):\/\//iu;
const WINDOWS_PATH = /(?:^|[\s("'=])[A-Za-z]:\\[^\s]+/u;
const UNIX_HOST_PATH = /(?:^|[\s("'=])\/(?!\/)[^\s,;)}\]]+/u;
const RELATIVE_HOST_PATH = /(?:^|[\s("'=])(?:\.{1,2}|~)[/\\][^\s]+/u;

function bounded(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > maximum) {
    throw invalidInput(`${label} must contain 1-${maximum} characters.`);
  }
  if (normalized.includes(String.fromCharCode(0))) {
    throw invalidInput(`${label} contains a null byte.`);
  }
  if (
    URL.test(normalized) ||
    WINDOWS_PATH.test(normalized) ||
    UNIX_HOST_PATH.test(normalized) ||
    RELATIVE_HOST_PATH.test(normalized)
  ) {
    throw invalidInput(`${label} must not contain a URL or host filesystem path.`);
  }
  return normalized;
}

export function decodeIncidentInput(value: unknown): IncidentInput {
  let input: typeof IncidentInputSchema.Type;
  try {
    input = decodeIncidentShape(value);
  } catch (cause) {
    throw invalidInput("IncidentInput v1 does not match the strict schema.", cause);
  }

  const request = bounded(input.request, "request", MAX_INCIDENT_TEXT);
  const observations = input.observations ?? [];
  if (observations.length > MAX_OBSERVATIONS) {
    throw invalidInput(`observations must contain at most ${MAX_OBSERVATIONS} entries.`);
  }
  const ids = new Set<string>();
  const normalizedObservations = observations.map((observation, index) => {
    const observationId = bounded(
      observation.observation_id,
      `observations[${index}].observation_id`,
      64,
    );
    const kind = bounded(observation.kind, `observations[${index}].kind`, 64);
    if (!SAFE_ID.test(observationId)) {
      throw invalidInput(`observations[${index}].observation_id is invalid.`);
    }
    if (!SAFE_KIND.test(kind)) throw invalidInput(`observations[${index}].kind is invalid.`);
    if (ids.has(observationId)) throw invalidInput(`Duplicate observation_id: ${observationId}.`);
    ids.add(observationId);

    const raw = observation.value;
    if (typeof raw !== "string" && typeof raw !== "number" && typeof raw !== "boolean") {
      throw invalidInput(`observations[${index}].value must be a string, number, or boolean.`);
    }
    if (typeof raw === "number" && !Number.isFinite(raw)) {
      throw invalidInput(`observations[${index}].value must be finite.`);
    }
    const normalizedValue =
      typeof raw === "string"
        ? bounded(raw, `observations[${index}].value`, MAX_OBSERVATION_TEXT)
        : raw;
    const unit =
      observation.unit === undefined
        ? undefined
        : bounded(observation.unit, `observations[${index}].unit`, 32);
    return {
      observation_id: observationId,
      kind,
      value: normalizedValue,
      ...(unit === undefined ? {} : { unit }),
    } satisfies StructuredObservation;
  });

  const ticketRef =
    input.ticket_ref === undefined ? undefined : bounded(input.ticket_ref, "ticket_ref", 20);
  if (ticketRef !== undefined && !TICKET_REF.test(ticketRef)) {
    throw invalidInput("ticket_ref must be an exact Jira-like issue key.");
  }
  const reportedPriority =
    input.reported_priority === undefined
      ? undefined
      : bounded(input.reported_priority, "reported_priority", 16);
  if (reportedPriority !== undefined && !PRIORITY.test(reportedPriority)) {
    throw invalidInput("reported_priority is unrecognized metadata.");
  }
  const pcapArtifactId = input.pcap_artifact_id;
  if (pcapArtifactId !== undefined && !ARTIFACT_ID.test(pcapArtifactId)) {
    throw invalidInput("pcap_artifact_id must be a content-addressed PCAP artifact ID.");
  }

  return {
    schema_version: "1",
    request,
    observations: normalizedObservations,
    ...(ticketRef === undefined ? {} : { ticket_ref: ticketRef }),
    ...(reportedPriority === undefined ? {} : { reported_priority: reportedPriority }),
    ...(pcapArtifactId === undefined ? {} : { pcap_artifact_id: pcapArtifactId }),
  };
}

export function isPcapArtifactId(value: string): boolean {
  return ARTIFACT_ID.test(value);
}

export function decodePcapSecurityTriageInput(value: unknown): PcapSecurityTriageInput {
  let input: typeof PcapSecurityTriageInputSchema.Type;
  try {
    input = decodePcapSecurityTriageShape(value);
  } catch (cause) {
    throw invalidInput("PcapSecurityTriageInput v1 does not match the strict schema.", cause);
  }
  if (!ARTIFACT_ID.test(input.pcap_artifact_id)) {
    throw invalidInput("pcap_artifact_id must be a content-addressed PCAP artifact ID.");
  }
  return input;
}

export function isExerciseSnapshotId(value: string): boolean {
  return EXERCISE_SNAPSHOT_ID.test(value);
}

export function decodeExerciseSolveInput(value: unknown): ExerciseSolveInput {
  let input: typeof ExerciseSolveInputSchema.Type;
  try {
    input = decodeExerciseSolveShape(value);
  } catch (cause) {
    throw invalidInput("ExerciseSolveInput v1 does not match the strict schema.", cause);
  }
  if (!EXERCISE_SNAPSHOT_ID.test(input.exercise_snapshot_id)) {
    throw invalidInput("exercise_snapshot_id must be a content-addressed exercise snapshot ID.");
  }
  return input;
}
