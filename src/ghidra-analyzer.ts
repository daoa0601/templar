import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { runBoundedProcess } from "@agentic-orch/node-guardrails";

import { invalidInput } from "./errors.js";

const MACOS_DENY_NETWORK_PROFILE = "(version 1) (allow default) (deny network*)";

export interface GhidraDecompilation {
  readonly analyzer_id: "ghidra-headless";
  readonly analyzer_version: string;
  readonly text: string;
}

function absolutePath(value: string, label: string): string {
  if (!path.isAbsolute(value) || value.includes(String.fromCharCode(0))) {
    throw invalidInput(`${label} must be an absolute path.`);
  }
  return path.normalize(value);
}

/**
 * Run Ghidra headlessly behind macOS's deny-network sandbox. The specimen and project live in a
 * private temporary directory, and only the bounded decompiler text is returned.
 */
export async function runGhidraDecompilation(options: {
  readonly bytes: Uint8Array;
  readonly analyzeHeadlessPath: string;
  readonly scriptDirectory: string;
  readonly javaHome: string;
  readonly analyzerVersion: string;
  readonly sandboxExecutable?: string;
  readonly maxOutputBytes?: number;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}): Promise<GhidraDecompilation> {
  if (process.platform !== "darwin") {
    throw invalidInput("Ghidra course analysis currently requires the macOS deny-network sandbox.");
  }
  if (options.bytes.byteLength === 0 || options.bytes.byteLength > 256 * 1024 * 1024) {
    throw invalidInput("The Ghidra specimen is empty or exceeds the byte limit.");
  }
  const maximum = options.maxOutputBytes ?? 8 * 1024 * 1024;
  if (!Number.isSafeInteger(maximum) || maximum <= 0 || maximum > 32 * 1024 * 1024) {
    throw invalidInput("The Ghidra output limit is invalid.");
  }
  const analyzeHeadless = absolutePath(options.analyzeHeadlessPath, "analyzeHeadlessPath");
  const scriptDirectory = absolutePath(options.scriptDirectory, "scriptDirectory");
  const javaHome = absolutePath(options.javaHome, "javaHome");
  const sandbox = absolutePath(
    options.sandboxExecutable ?? "/usr/bin/sandbox-exec",
    "sandboxExecutable",
  );
  const version = options.analyzerVersion.trim();
  if (!/^[0-9]+\.[0-9]+(?:\.[0-9]+)?$/u.test(version)) {
    throw invalidInput("The Ghidra analyzer version is invalid.");
  }

  const root = await mkdtemp(path.join(os.tmpdir(), "templar-ghidra-"));
  const specimenPath = path.join(root, "specimen.exe");
  const outputPath = path.join(root, "decompiled.txt");
  try {
    await writeFile(specimenPath, options.bytes, { mode: 0o600 });
    const result = await runBoundedProcess({
      executable: sandbox,
      args: [
        "-p",
        MACOS_DENY_NETWORK_PROFILE,
        analyzeHeadless,
        root,
        "analysis",
        "-import",
        specimenPath,
        "-scriptPath",
        scriptDirectory,
        "-postScript",
        "ExportDecompilation.java",
        outputPath,
        String(maximum),
        "-analysisTimeoutPerFile",
        String(Math.max(1, Math.floor((options.timeoutMs ?? 5 * 60_000) / 1000))),
        "-deleteProject",
      ],
      cwd: root,
      env: {
        JAVA_HOME: javaHome,
        PATH: process.env.PATH,
        LANG: process.env.LANG ?? "C.UTF-8",
        LC_ALL: process.env.LC_ALL,
      },
      timeoutMs: options.timeoutMs ?? 5 * 60_000,
      maxOutputBytes: 4 * 1024 * 1024,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (result.exitCode !== 0) throw invalidInput("Ghidra headless analysis failed.");
    const outputStat = await stat(outputPath);
    if (!outputStat.isFile() || outputStat.size <= 0 || outputStat.size > maximum) {
      throw invalidInput("Ghidra produced an invalid decompilation artifact.");
    }
    const text = await readFile(outputPath, "utf8");
    if (!text.startsWith("PROGRAM ") || text.includes(String.fromCharCode(0))) {
      throw invalidInput("Ghidra produced malformed decompilation text.");
    }
    return { analyzer_id: "ghidra-headless", analyzer_version: version, text };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
