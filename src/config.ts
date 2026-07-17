import os from "node:os";
import path from "node:path";

import { invalidInput } from "./errors.js";

export interface TemplarConfig {
  readonly host: string;
  readonly port: number;
  readonly templarHome: string;
  readonly artifactRoot: string;
  readonly harnessHome: string;
  readonly bearerToken?: string;
  readonly maxActiveRuns: number;
  readonly maxJsonBytes: number;
  readonly maxPcapBytes: number;
  readonly maxPcapPackets: number;
}

function integer(value: string | undefined, fallback: number, label: string): number {
  if (value === undefined || value.length === 0) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw invalidInput(`${label} must be a positive integer.`);
  }
  return parsed;
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
  };
}
