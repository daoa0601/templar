import {
  decodeDroneBaseUrl as decodeBaseUrl,
  DroneClient as HttpDroneClient,
  DroneClientError,
} from "@agentic-orch/drone-client";
import type {
  DroneCallOptions,
  DroneClientOptions,
  DroneArtifactMetadata,
  DroneJob,
  DroneJobSubmission,
  DroneProviderStatus,
  DronePublicOperation,
} from "@agentic-orch/drone-client";

import { invalidInput, TemplarError } from "./errors.js";

export type {
  DroneArtifactMetadata,
  DroneJob,
  DroneJobSubmission,
  DroneProviderStatus,
  DronePublicOperation,
} from "@agentic-orch/drone-client";

function mappedError(cause: unknown): TemplarError {
  if (cause instanceof TemplarError) return cause;
  if (
    cause instanceof DroneClientError &&
    (cause.code === "INVALID_BASE_URL" || cause.code === "INVALID_REQUEST")
  ) {
    return invalidInput(cause.message, cause);
  }
  return new TemplarError({
    code: "SERVICE_UNAVAILABLE",
    message: "Drone is unavailable.",
    status: 503,
    expose: false,
    cause,
  });
}

export function decodeDroneBaseUrl(value: string): URL {
  try {
    return decodeBaseUrl(value);
  } catch (cause) {
    throw mappedError(cause);
  }
}

export function droneUnavailableStatus(reason: string): DroneProviderStatus {
  return {
    provider_id: "drone",
    product: "Drone sandbox service",
    installed: false,
    enabled: false,
    mutations_available: false,
    reason,
    isolation: "lightweight_vm",
    guest_os: ["linux"],
    network_modes: ["none"],
  };
}

/** Templar error adapter around the shared Drone HTTP client. */
export class DroneClient {
  readonly #client: HttpDroneClient;

  constructor(options: DroneClientOptions) {
    try {
      this.#client = new HttpDroneClient(options);
    } catch (cause) {
      throw mappedError(cause);
    }
  }

  async providers(options: DroneCallOptions = {}): Promise<ReadonlyArray<DroneProviderStatus>> {
    try {
      return await this.#client.providers(options);
    } catch (cause) {
      throw mappedError(cause);
    }
  }

  async operations(options: DroneCallOptions = {}): Promise<ReadonlyArray<DronePublicOperation>> {
    try {
      return await this.#client.operations(options);
    } catch (cause) {
      throw mappedError(cause);
    }
  }

  async stageArtifact(
    bytes: Uint8Array,
    mediaType: string,
    options: DroneCallOptions = {},
  ): Promise<DroneArtifactMetadata> {
    try {
      return await this.#client.stageArtifact(bytes, mediaType, options);
    } catch (cause) {
      throw mappedError(cause);
    }
  }

  async submitJob(input: DroneJobSubmission, options: DroneCallOptions = {}): Promise<DroneJob> {
    try {
      return await this.#client.submitJob(input, options);
    } catch (cause) {
      throw mappedError(cause);
    }
  }

  async job(jobId: string, options: DroneCallOptions = {}): Promise<DroneJob> {
    try {
      return await this.#client.job(jobId, options);
    } catch (cause) {
      throw mappedError(cause);
    }
  }
}
