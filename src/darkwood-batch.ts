import { spawn } from "node:child_process";
import { once } from "node:events";

import { analyzeDarkwoodSample, type DarkwoodAnalysis } from "./course-analyzers.js";
import { invalidInput } from "./errors.js";
import {
  listSevenZipMembers,
  sevenZipEnvironment,
  sevenZipExtractToStdoutArgs,
  sevenZipPasswordStdin,
  type SevenZipMember,
} from "./seven-zip.js";

export const DARKWOOD_EXPECTED_SAMPLE_COUNT = 60;
export const DARKWOOD_EXPECTED_SAMPLE_BYTES = 69_154_119;
const DARKWOOD_NAME = /^darkwood_[a-z0-9]+\.exe$/iu;

export interface DarkwoodBatchAnalysis {
  readonly schema_version: "1";
  readonly analyzer_id: "templar.darkwood-passive";
  readonly analyzer_version: "1.0.0";
  readonly sample_count: number;
  readonly results: ReadonlyArray<DarkwoodAnalysis>;
}

export async function analyzeDarkwoodMemberStream(
  chunks: AsyncIterable<Uint8Array>,
  members: ReadonlyArray<SevenZipMember>,
): Promise<ReadonlyArray<DarkwoodAnalysis>> {
  if (members.length === 0 || members.length > DARKWOOD_EXPECTED_SAMPLE_COUNT) {
    throw invalidInput("The Darkwood member stream has an invalid sample count.");
  }
  const maximumBytes = members.reduce((sum, member) => {
    if (!Number.isSafeInteger(member.size) || member.size <= 0 || member.size > 96 * 1024 * 1024) {
      throw invalidInput(`Darkwood stream member ${member.path} has an invalid size.`);
    }
    const next = sum + member.size;
    if (!Number.isSafeInteger(next) || next > 6 * 1024 * 1024 * 1024) {
      throw invalidInput("The Darkwood member stream exceeds its aggregate byte limit.");
    }
    return next;
  }, 0);
  const results: DarkwoodAnalysis[] = [];
  let memberIndex = 0;
  let sample = Buffer.allocUnsafe(members[0]!.size);
  let sampleOffset = 0;
  let totalBytes = 0;

  for await (const inputChunk of chunks) {
    const chunk = Buffer.from(inputChunk.buffer, inputChunk.byteOffset, inputChunk.byteLength);
    let chunkOffset = 0;
    totalBytes += chunk.length;
    if (totalBytes > maximumBytes) throw invalidInput("The Darkwood stream exceeds its listing.");
    while (chunkOffset < chunk.length) {
      const member = members[memberIndex];
      if (member === undefined) throw invalidInput("The Darkwood stream contains trailing bytes.");
      const copied = Math.min(sample.length - sampleOffset, chunk.length - chunkOffset);
      chunk.copy(sample, sampleOffset, chunkOffset, chunkOffset + copied);
      sampleOffset += copied;
      chunkOffset += copied;
      if (sampleOffset === sample.length) {
        results.push(analyzeDarkwoodSample(sample, member.path));
        memberIndex += 1;
        const next = members[memberIndex];
        if (next !== undefined) sample = Buffer.allocUnsafe(next.size);
        sampleOffset = 0;
      }
    }
  }
  if (memberIndex !== members.length || sampleOffset !== 0 || totalBytes !== maximumBytes) {
    throw invalidInput("The Darkwood member stream ended before the declared samples.");
  }
  return results;
}

function validateDarkwoodMembers(
  members: ReadonlyArray<SevenZipMember>,
): ReadonlyArray<SevenZipMember> {
  if (members.length !== DARKWOOD_EXPECTED_SAMPLE_COUNT) {
    throw invalidInput(`Expected ${DARKWOOD_EXPECTED_SAMPLE_COUNT} Darkwood samples.`);
  }
  for (const member of members) {
    if (
      !DARKWOOD_NAME.test(member.path) ||
      member.path.includes("/") ||
      member.path.includes("\\") ||
      member.size !== DARKWOOD_EXPECTED_SAMPLE_BYTES ||
      !member.encrypted
    ) {
      throw invalidInput(`Darkwood archive member ${member.path} violates the corpus contract.`);
    }
  }
  return members;
}

/**
 * Decrypt all 60 solid-archive samples in one 7-Zip pass and analyze each apphost as passive bytes.
 * No member is written to disk or executed.
 */
export async function analyzeDarkwoodArchive(options: {
  readonly executable: string;
  readonly archivePath: string;
  readonly password: string;
  readonly cwd: string;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}): Promise<DarkwoodBatchAnalysis> {
  const members = validateDarkwoodMembers(await listSevenZipMembers(options));
  if (options.signal?.aborted === true) throw invalidInput("Darkwood analysis was aborted.");
  const passwordInput = sevenZipPasswordStdin(options.password);
  const child = spawn(
    options.executable,
    sevenZipExtractToStdoutArgs(options.archivePath, members),
    {
      cwd: options.cwd,
      env: sevenZipEnvironment(),
      shell: false,
      detached: process.platform !== "win32",
      stdio: ["pipe", "pipe", "pipe"],
    },
  );
  const completion = once(child, "close") as Promise<[number | null, NodeJS.Signals | null]>;
  let stderr = "";
  let terminalError: unknown;

  const terminate = (): void => {
    try {
      if (process.platform !== "win32" && child.pid !== undefined)
        process.kill(-child.pid, "SIGKILL");
      else child.kill("SIGKILL");
    } catch {
      // The process may have exited between the state check and signal delivery.
    }
  };
  child.once("error", (cause) => {
    terminalError = invalidInput("Unable to launch 7-Zip for Darkwood analysis.", cause);
  });
  child.stdin!.once("error", (cause) => {
    terminalError = invalidInput("Unable to supply the Darkwood archive password.", cause);
    terminate();
  });
  child.stdin!.end(passwordInput);
  child.stderr!.setEncoding("utf8");
  child.stderr!.on("data", (chunk: string) => {
    stderr += chunk;
    if (stderr.length > 1024 * 1024) {
      terminalError = invalidInput("7-Zip exceeded the Darkwood diagnostic output limit.");
      terminate();
    }
  });
  const abort = (): void => {
    terminalError = invalidInput("Darkwood analysis was aborted.");
    terminate();
  };
  options.signal?.addEventListener("abort", abort, { once: true });
  const timeout = setTimeout(
    () => {
      terminalError = invalidInput("Darkwood analysis exceeded its wall-clock limit.");
      terminate();
    },
    options.timeoutMs ?? 10 * 60_000,
  );

  let results: ReadonlyArray<DarkwoodAnalysis> = [];
  try {
    results = await analyzeDarkwoodMemberStream(child.stdout!, members);
  } catch (cause) {
    terminalError = cause;
    terminate();
  }
  const [exitCode] = await completion;
  clearTimeout(timeout);
  options.signal?.removeEventListener("abort", abort);
  if (terminalError !== undefined) throw terminalError;
  if (exitCode !== 0) {
    throw invalidInput(
      `7-Zip could not stream the Darkwood archive: ${stderr.trim().slice(0, 512)}`,
    );
  }
  return {
    schema_version: "1",
    analyzer_id: "templar.darkwood-passive",
    analyzer_version: "1.0.0",
    sample_count: results.length,
    results,
  };
}
