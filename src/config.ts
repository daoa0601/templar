import os from "node:os";
import path from "node:path";

import { invalidInput } from "./errors.js";

export interface TemplarConfig {
  readonly host: string;
  readonly port: number;
  readonly templarHome: string;
  readonly artifactRoot: string;
  readonly exerciseArtifactRoot: string;
  readonly sourceArtifactRoot: string;
  readonly harnessHome: string;
  readonly bearerToken?: string;
  readonly maxActiveRuns: number;
  readonly maxJsonBytes: number;
  readonly maxPcapBytes: number;
  readonly maxPcapPackets: number;
  readonly maxExerciseSnapshotBytes: number;
  readonly maxCourseLabSpecimenBytes: number;
  readonly maxSourceSnapshotBytes: number;
  readonly droneEnabled: boolean;
  readonly droneUrl: string;
  readonly droneToken?: string;
  readonly droneTimeoutMs: number;
  readonly droneSourceValidationOperationId?: string;
  readonly droneCourseLabOperationId?: string;
}

function integer(value: string | undefined, fallback: number, label: string): number {
  if (value === undefined || value.length === 0) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw invalidInput(`${label} must be a positive integer.`);
  }
  return parsed;
}

function boolean(value: string | undefined, fallback: boolean, label: string): boolean {
  if (value === undefined || value.length === 0) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw invalidInput(`${label} must be true or false.`);
}

export function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): TemplarConfig {
  const host = environment.TEMPLAR_HOST?.trim() || "127.0.0.1";
  const configuredHome = environment.TEMPLAR_HOME?.trim() || path.join(os.homedir(), ".templar");
  const templarHome = path.resolve(configuredHome);
  const token = environment.TEMPLAR_BEARER_TOKEN?.trim();
  const droneToken = environment.TEMPLAR_DRONE_TOKEN?.trim();
  const droneSourceValidationOperationId =
    environment.TEMPLAR_DRONE_SOURCE_VALIDATION_OPERATION_ID?.trim();
  const droneCourseLabOperationId = environment.TEMPLAR_DRONE_COURSE_LAB_OPERATION_ID?.trim();
  if (!isLoopbackHost(host) && !token) {
    throw invalidInput("TEMPLAR_BEARER_TOKEN is required when TEMPLAR_HOST is not loopback.");
  }
  if (
    droneSourceValidationOperationId !== undefined &&
    droneSourceValidationOperationId.length > 0 &&
    !/^[a-z][a-z0-9_.-]{0,127}$/u.test(droneSourceValidationOperationId)
  ) {
    throw invalidInput(
      "TEMPLAR_DRONE_SOURCE_VALIDATION_OPERATION_ID must be a safe Drone operation ID.",
    );
  }
  if (
    droneCourseLabOperationId !== undefined &&
    droneCourseLabOperationId.length > 0 &&
    !/^[a-z][a-z0-9_.-]{0,127}$/u.test(droneCourseLabOperationId)
  ) {
    throw invalidInput("TEMPLAR_DRONE_COURSE_LAB_OPERATION_ID must be a safe Drone operation ID.");
  }
  return {
    host,
    port: integer(environment.TEMPLAR_PORT, 8080, "TEMPLAR_PORT"),
    templarHome,
    artifactRoot: path.join(templarHome, "artifacts", "pcap"),
    exerciseArtifactRoot: path.join(templarHome, "artifacts", "exercise"),
    sourceArtifactRoot: path.join(templarHome, "artifacts", "source"),
    harnessHome: path.join(templarHome, "harness"),
    ...(token === undefined || token.length === 0 ? {} : { bearerToken: token }),
    maxActiveRuns: integer(environment.TEMPLAR_MAX_ACTIVE_RUNS, 2, "TEMPLAR_MAX_ACTIVE_RUNS"),
    maxJsonBytes: integer(environment.TEMPLAR_MAX_JSON_BYTES, 64 * 1024, "TEMPLAR_MAX_JSON_BYTES"),
    maxPcapBytes: integer(
      environment.TEMPLAR_MAX_PCAP_BYTES,
      8 * 1024 * 1024,
      "TEMPLAR_MAX_PCAP_BYTES",
    ),
    maxPcapPackets: integer(
      environment.TEMPLAR_MAX_PCAP_PACKETS,
      50_000,
      "TEMPLAR_MAX_PCAP_PACKETS",
    ),
    maxExerciseSnapshotBytes: integer(
      environment.TEMPLAR_MAX_EXERCISE_SNAPSHOT_BYTES,
      512 * 1024,
      "TEMPLAR_MAX_EXERCISE_SNAPSHOT_BYTES",
    ),
    maxCourseLabSpecimenBytes: integer(
      environment.TEMPLAR_MAX_COURSE_LAB_SPECIMEN_BYTES,
      256 * 1024 * 1024,
      "TEMPLAR_MAX_COURSE_LAB_SPECIMEN_BYTES",
    ),
    maxSourceSnapshotBytes: integer(
      environment.TEMPLAR_MAX_SOURCE_SNAPSHOT_BYTES,
      8 * 1024 * 1024,
      "TEMPLAR_MAX_SOURCE_SNAPSHOT_BYTES",
    ),
    droneEnabled: boolean(environment.TEMPLAR_DRONE_ENABLED, true, "TEMPLAR_DRONE_ENABLED"),
    droneUrl: environment.TEMPLAR_DRONE_URL?.trim() || "http://127.0.0.1:8090",
    ...(droneToken === undefined || droneToken.length === 0 ? {} : { droneToken }),
    droneTimeoutMs: integer(
      environment.TEMPLAR_DRONE_TIMEOUT_MS,
      1_000,
      "TEMPLAR_DRONE_TIMEOUT_MS",
    ),
    ...(droneSourceValidationOperationId === undefined ||
    droneSourceValidationOperationId.length === 0
      ? {}
      : { droneSourceValidationOperationId }),
    ...(droneCourseLabOperationId === undefined || droneCourseLabOperationId.length === 0
      ? {}
      : { droneCourseLabOperationId }),
  };
}
