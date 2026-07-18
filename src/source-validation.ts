import { lstat, readdir, readFile } from "node:fs/promises";
import path from "node:path";

import type { DronePublicOperation } from "./drone-client.js";
import { TemplarError, invalidInput } from "./errors.js";
import { decodeSourceSnapshot, normalizeSourcePath } from "./source.js";
import type { SourceSnapshot } from "./source.js";

export const SOURCE_VALIDATION_MEDIA_TYPE = "application/vnd.templar.source-tree+json";
export const SOURCE_VALIDATION_INPUT_SLOT = "source";
export const SOURCE_VALIDATION_OUTPUT_SLOT = "validation";

async function collectFiles(root: string, maximumBytes: number): Promise<SourceSnapshot["files"]> {
  const files: Array<{ readonly path: string; readonly content: string }> = [];
  let observedBytes = 0;

  async function visit(directory: string, prefix: string): Promise<void> {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const relative = normalizeSourcePath(
        prefix.length === 0 ? entry.name : `${prefix}/${entry.name}`,
        "accepted source path",
      );
      const absolute = path.join(root, ...relative.split("/"));
      const info = await lstat(absolute);
      if (info.isSymbolicLink()) {
        throw new TemplarError({
          code: "CONFLICT",
          message: "The accepted source tree contains a symbolic link.",
          status: 409,
        });
      }
      if (info.isDirectory()) {
        await visit(absolute, relative);
        continue;
      }
      if (!info.isFile()) {
        throw new TemplarError({
          code: "CONFLICT",
          message: "The accepted source tree contains an unsupported filesystem object.",
          status: 409,
        });
      }
      observedBytes += info.size;
      if (observedBytes > maximumBytes) {
        throw new TemplarError({
          code: "SOURCE_LIMIT_EXCEEDED",
          message: `The accepted source tree exceeds the ${maximumBytes}-byte validation limit.`,
          status: 413,
        });
      }
      files.push({ path: relative, content: await readFile(absolute, "utf8") });
    }
  }

  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
    throw new TemplarError({
      code: "CONFLICT",
      message: "The accepted source target is not a real directory.",
      status: 409,
    });
  }
  await visit(root, "");
  return files;
}

export async function buildSourceValidationArtifact(options: {
  readonly targetRoot: string;
  readonly repository: SourceSnapshot["repository"];
  readonly maximumBytes: number;
}): Promise<Uint8Array> {
  const snapshot = decodeSourceSnapshot({
    schema_version: "1",
    repository: options.repository,
    files: await collectFiles(options.targetRoot, options.maximumBytes),
  });
  const bytes = Buffer.from(`${JSON.stringify(snapshot)}\n`, "utf8");
  if (bytes.byteLength > options.maximumBytes) {
    throw new TemplarError({
      code: "SOURCE_LIMIT_EXCEEDED",
      message: `The accepted source tree exceeds the ${options.maximumBytes}-byte validation limit.`,
      status: 413,
    });
  }
  return bytes;
}

export function assertSourceValidationOperation(
  operation: DronePublicOperation,
  artifactBytes: number,
): void {
  const source = operation.inputs.find((slot) => slot.name === SOURCE_VALIDATION_INPUT_SLOT);
  const validation = operation.outputs.find((slot) => slot.name === SOURCE_VALIDATION_OUTPUT_SLOT);
  const valid =
    operation.enabled &&
    operation.network === "none" &&
    source?.required === true &&
    source.max_bytes >= artifactBytes &&
    source.media_types.includes(SOURCE_VALIDATION_MEDIA_TYPE) &&
    operation.inputs.every(
      (slot) => !slot.required || slot.name === SOURCE_VALIDATION_INPUT_SLOT,
    ) &&
    validation?.required === true &&
    validation.media_type === "application/json";
  if (!valid) {
    throw new TemplarError({
      code: "CONFLICT",
      message:
        "The configured Drone operation does not satisfy Templar's no-network source-validation contract.",
      status: 409,
    });
  }
}

export function validationRationale(value: string): string {
  const normalized = value.trim();
  if (
    normalized.length < 8 ||
    normalized.length > 500 ||
    /\p{Cc}/u.test(normalized) ||
    /\b(?:https?|file):\/\/|(?:^|\s)\/(?:etc|home|root|tmp|usr|var)\//iu.test(normalized)
  ) {
    throw invalidInput("Validation rationale must contain 8-500 safe characters.");
  }
  return normalized;
}
