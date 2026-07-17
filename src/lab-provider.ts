import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";
import path from "node:path";

import { assertRunId } from "aiur-orchestrator";

import { invalidInput } from "./errors.js";

export type LabOperationId = "exercise.static_pe_snapshot";

export interface LabProviderStatus {
  readonly provider_id: "parallels_desktop";
  readonly product: "Parallels Desktop";
  readonly installed: boolean;
  readonly enabled: boolean;
  readonly mutations_available: false;
  readonly reason: string;
}

export interface LabCommandPlan {
  readonly executable: string;
  readonly args: ReadonlyArray<string>;
  readonly mutating: true;
  readonly operation: "clone" | "restore" | "start" | "exec" | "capture" | "stop";
}

export interface ParallelsDesktopOptions {
  readonly enabled: boolean;
  readonly cliPath: string;
  readonly quarantineRoot: string;
}

const UUID = /^\{?[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\}?$/iu;

function identifier(value: string, label: string): string {
  const normalized = value.trim();
  if (!UUID.test(normalized)) throw invalidInput(`${label} must be an exact UUID.`);
  return normalized;
}

function requireEnabled(options: ParallelsDesktopOptions): void {
  if (!options.enabled) {
    throw invalidInput("Parallels Desktop lab mutations are disabled by configuration.");
  }
}

function runOwnedName(runId: string): string {
  assertRunId(runId);
  return `templar-${createHash("sha256").update(runId).digest("hex").slice(0, 20)}`;
}

export async function parallelsDesktopStatus(
  options: ParallelsDesktopOptions,
): Promise<LabProviderStatus> {
  let installed = false;
  try {
    installed = (await stat(options.cliPath)).isFile();
  } catch {
    installed = false;
  }
  const enabled = options.enabled && installed;
  return {
    provider_id: "parallels_desktop",
    product: "Parallels Desktop",
    installed,
    enabled,
    mutations_available: false,
    reason: !installed
      ? "prlctl_not_found"
      : !options.enabled
        ? "disabled_by_configuration"
        : "provider_boundary_ready_but_no_vm_is_allowlisted",
  };
}

/**
 * Builds shell-free `prlctl` argv for a future attested provider. It deliberately does not execute
 * commands and accepts no arbitrary guest command or output path.
 */
export class ParallelsDesktopCommandPlanner {
  readonly #options: ParallelsDesktopOptions;

  constructor(options: ParallelsDesktopOptions) {
    this.#options = {
      enabled: options.enabled,
      cliPath: path.resolve(options.cliPath),
      quarantineRoot: path.resolve(options.quarantineRoot),
    };
  }

  cloneFromSnapshot(options: {
    readonly runId: string;
    readonly baseVmId: string;
    readonly snapshotId: string;
  }): { readonly labName: string; readonly plan: LabCommandPlan } {
    requireEnabled(this.#options);
    const labName = runOwnedName(options.runId);
    const baseVmId = identifier(options.baseVmId, "baseVmId");
    const snapshotId = identifier(options.snapshotId, "snapshotId");
    return {
      labName,
      plan: {
        executable: this.#options.cliPath,
        args: [
          "clone",
          baseVmId,
          "--name",
          labName,
          "--dst",
          path.join(this.#options.quarantineRoot, labName),
          "--linked",
          "-i",
          snapshotId,
          "--detach-external-hdd",
          "yes",
        ],
        mutating: true,
        operation: "clone",
      },
    };
  }

  restore(labId: string, snapshotId: string): LabCommandPlan {
    requireEnabled(this.#options);
    return {
      executable: this.#options.cliPath,
      args: [
        "snapshot-switch",
        identifier(labId, "labId"),
        "-i",
        identifier(snapshotId, "snapshotId"),
        "--skip-resume",
      ],
      mutating: true,
      operation: "restore",
    };
  }

  start(labId: string): LabCommandPlan {
    requireEnabled(this.#options);
    return {
      executable: this.#options.cliPath,
      args: ["start", identifier(labId, "labId")],
      mutating: true,
      operation: "start",
    };
  }

  execute(labId: string, operationId: LabOperationId): LabCommandPlan {
    requireEnabled(this.#options);
    const guestCommand: Record<LabOperationId, string> = {
      "exercise.static_pe_snapshot": "C:\\Templar\\capture-static-pe.cmd",
    };
    return {
      executable: this.#options.cliPath,
      args: ["exec", identifier(labId, "labId"), guestCommand[operationId]],
      mutating: true,
      operation: "exec",
    };
  }

  capture(runId: string, labId: string): LabCommandPlan {
    requireEnabled(this.#options);
    const labName = runOwnedName(runId);
    return {
      executable: this.#options.cliPath,
      args: [
        "capture",
        identifier(labId, "labId"),
        "--file",
        path.join(this.#options.quarantineRoot, labName, "screen.png"),
      ],
      mutating: true,
      operation: "capture",
    };
  }

  stop(labId: string, force = false): LabCommandPlan {
    requireEnabled(this.#options);
    return {
      executable: this.#options.cliPath,
      args: ["stop", identifier(labId, "labId"), ...(force ? ["--kill"] : [])],
      mutating: true,
      operation: "stop",
    };
  }
}
