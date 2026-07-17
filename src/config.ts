import os from "node:os";
import path from "node:path";

import { invalidInput } from "./errors.js";

export interface TemplarConfig {
  readonly host: string;
  readonly port: number;
  readonly templarHome: string;
  readonly artifactRoot: string;
  readonly exerciseArtifactRoot: string;
  readonly harnessHome: string;
  readonly bearerToken?: string;
  readonly maxActiveRuns: number;
  readonly maxJsonBytes: number;
  readonly maxPcapBytes: number;
  readonly maxPcapPackets: number;
  readonly maxExerciseSnapshotBytes: number;
  readonly parallelsDesktopEnabled: boolean;
  readonly parallelsCliPath: string;
  readonly parallelsQuarantineRoot: string;
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
  if (!isLoopbackHost(host) && !token) {
    throw invalidInput("TEMPLAR_BEARER_TOKEN is required when TEMPLAR_HOST is not loopback.");
  }
  return {
    host,
    port: integer(environment.TEMPLAR_PORT, 8080, "TEMPLAR_PORT"),
    templarHome,
    artifactRoot: path.join(templarHome, "artifacts", "pcap"),
    exerciseArtifactRoot: path.join(templarHome, "artifacts", "exercise"),
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
    parallelsDesktopEnabled: boolean(
      environment.TEMPLAR_PARALLELS_DESKTOP_ENABLED,
      false,
      "TEMPLAR_PARALLELS_DESKTOP_ENABLED",
    ),
    parallelsCliPath: path.resolve(
      environment.TEMPLAR_PARALLELS_CLI?.trim() || "/usr/local/bin/prlctl",
    ),
    parallelsQuarantineRoot: path.resolve(
      environment.TEMPLAR_PARALLELS_QUARANTINE_ROOT?.trim() ||
        path.join(templarHome, "labs", "parallels"),
    ),
  };
}
