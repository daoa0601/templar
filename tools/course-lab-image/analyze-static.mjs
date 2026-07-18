import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { open, rm, writeFile } from "node:fs/promises";

const INPUT_SPECIMEN = "/drone/input/specimen";
const INPUT_CONTEXT = "/drone/input/context";
const OUTPUT_EVIDENCE = "/drone/output/evidence";
const EXPECTED_MEMBERS = ["instructions.txt", "static-161ca8b1.bin"];
const EXPECTED_REQUIREMENTS = Array.from(
  { length: 9 },
  (_, index) => `static-x86.q${String(index + 1).padStart(2, "0")}`,
);
const EXPECTED_CHECKS = ["pe_headers", "targeted_disassembly", "section_hex_dump"];
const SHA256 = /^[a-f0-9]{64}$/u;

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, keys) {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
  );
}

function exactArray(value, expected) {
  return (
    Array.isArray(value) &&
    value.length === expected.length &&
    value.every((item, index) => item === expected[index])
  );
}

async function boundedFile(file, maximum) {
  const handle = await open(file, "r");
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size <= 0n || before.size > BigInt(maximum)) {
      fail(`Invalid bounded input: ${file}`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      BigInt(bytes.byteLength) !== before.size ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    ) {
      fail(`Input changed while it was read: ${file}`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

async function runBounded(executable, args, options = {}) {
  const maximum = options.maximum ?? 1024 * 1024;
  const timeoutMs = options.timeoutMs ?? 30_000;
  const child = spawn(executable, args, {
    cwd: "/drone",
    env: { LANG: "C.UTF-8", LC_ALL: "C.UTF-8", PATH: "/usr/bin:/bin" },
    stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  let failure;
  const deadline = setTimeout(() => {
    failure = new Error(`Trusted analyzer timed out: ${executable}`);
    child.kill("SIGKILL");
  }, timeoutMs);
  child.stdout.on("data", (chunk) => {
    stdoutBytes += chunk.byteLength;
    if (stdoutBytes > maximum) {
      failure = new Error(`Trusted analyzer output exceeded ${maximum} bytes: ${executable}`);
      child.kill("SIGKILL");
      return;
    }
    stdout.push(chunk);
  });
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.byteLength;
    if (stderrBytes > 64 * 1024) {
      failure = new Error(`Trusted analyzer stderr exceeded its bound: ${executable}`);
      child.kill("SIGKILL");
      return;
    }
    stderr.push(chunk);
  });
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  if (options.input !== undefined) {
    child.stdin.on("error", (error) => {
      if (error.code !== "EPIPE") failure = error;
    });
    child.stdin.end(options.input);
  }
  const code = await completion.finally(() => clearTimeout(deadline));
  if (failure !== undefined) throw failure;
  if (code !== 0) {
    fail(
      `Trusted analyzer failed (${executable}, exit ${String(code)}): ${Buffer.concat(stderr).toString("utf8").trim()}`,
    );
  }
  return Buffer.concat(stdout);
}

function parseContext(bytes, specimen) {
  let context;
  try {
    context = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("Course-lab context is not JSON.");
  }
  if (
    !exactKeys(context, [
      "schema_version",
      "profile",
      "corpus_id",
      "assignment_id",
      "source_artifact_id",
      "analysis_mode",
      "requirement_ids",
      "required_check_ids",
      "assignment_artifact_ids",
      "specimen",
    ]) ||
    context.schema_version !== "1" ||
    context.profile !== "templar_course_assignment_lab_v1" ||
    context.corpus_id !== "aalto-cs-e433001-2025-v1" ||
    context.assignment_id !== "static-x86" ||
    context.source_artifact_id !== "static-x86-archive" ||
    context.analysis_mode !== "native_static" ||
    !exactArray(context.requirement_ids, EXPECTED_REQUIREMENTS) ||
    !exactArray(context.required_check_ids, EXPECTED_CHECKS) ||
    !exactArray(context.assignment_artifact_ids, ["static-x86-archive"]) ||
    !exactKeys(context.specimen, ["sha256", "size_bytes", "media_type", "exact_source_artifact"]) ||
    !SHA256.test(context.specimen.sha256) ||
    context.specimen.size_bytes !== specimen.byteLength ||
    context.specimen.media_type !== "application/zip" ||
    context.specimen.exact_source_artifact !== true
  ) {
    fail("Course-lab context does not authorize the static-x86 analyzer contract.");
  }
  const digest = createHash("sha256").update(specimen).digest("hex");
  if (digest !== context.specimen.sha256) fail("Specimen identity does not match context.");
  return context;
}

function parseQuestions(instructions, requirementIds) {
  const marker = instructions.indexOf("Questions");
  if (marker < 0) fail("Course instructions have no Questions section.");
  const block = instructions.slice(marker);
  const headings = [...block.matchAll(/^([1-9][0-9]*)\.\s+/gmu)];
  if (headings.length !== requirementIds.length) {
    fail(`Expected ${requirementIds.length} course questions, found ${headings.length}.`);
  }
  return headings.map((match, index) => {
    if (Number(match[1]) !== index + 1) fail("Course question numbering is not contiguous.");
    const next = headings[index + 1];
    const prompt = block.slice(match.index + match[0].length, next?.index).trim();
    if (prompt.length === 0 || prompt.length > 4_000 || prompt.includes("\0")) {
      fail("Course question prompt is invalid.");
    }
    return { question_id: requirementIds[index], prompt };
  });
}

async function objdump(samplePath, args, maximum = 160_000) {
  return (
    await runBounded("/usr/bin/x86_64-w64-mingw32-objdump", [...args, samplePath], {
      maximum,
    })
  )
    .toString("utf8")
    .trim();
}

async function main() {
  if (!exactArray(process.argv.slice(2), [INPUT_SPECIMEN, INPUT_CONTEXT, OUTPUT_EVIDENCE])) {
    fail("The static analyzer accepts only Drone's fixed exchange paths.");
  }
  const [specimen, contextBytes] = await Promise.all([
    boundedFile(INPUT_SPECIMEN, 16 * 1024 * 1024),
    boundedFile(INPUT_CONTEXT, 128 * 1024),
  ]);
  const context = parseContext(contextBytes, specimen);
  const listing = (
    await runBounded("/usr/bin/unzip", ["-Z1", INPUT_SPECIMEN], { maximum: 16 * 1024 })
  )
    .toString("utf8")
    .trim()
    .split(/\r?\n/u);
  if (!exactArray(listing, EXPECTED_MEMBERS)) fail("Static course archive members are unexpected.");
  const [instructionsBytes, sample, objdumpVersion] = await Promise.all([
    runBounded("/usr/bin/unzip", ["-p", INPUT_SPECIMEN, "instructions.txt"], {
      maximum: 128 * 1024,
    }),
    runBounded("/usr/bin/unzip", ["-p", INPUT_SPECIMEN, "static-161ca8b1.bin"], {
      maximum: 32 * 1024 * 1024,
    }),
    runBounded("/usr/bin/x86_64-w64-mingw32-objdump", ["--version"], {
      maximum: 32 * 1024,
    }),
  ]);
  const scratchSample = "/drone/output/.static-sample";
  await writeFile(scratchSample, sample, { flag: "wx", mode: 0o600 });
  let headers;
  let windowProcedure;
  let compareThunk;
  let sectionData;
  try {
    [headers, windowProcedure, compareThunk, sectionData] = await Promise.all([
      objdump(scratchSample, ["-x"]),
      objdump(scratchSample, [
        "-d",
        "--disassembler-options=intel",
        "--start-address=0x140001000",
        "--stop-address=0x140001280",
      ]),
      objdump(scratchSample, [
        "-d",
        "--disassembler-options=intel",
        "--start-address=0x140002140",
        "--stop-address=0x140002160",
      ]),
      objdump(scratchSample, ["-s", "-j", ".rdata", "-j", ".data"]),
    ]);
  } finally {
    await rm(scratchSample, { force: true });
  }
  for (const [label, text] of Object.entries({
    headers,
    windowProcedure,
    compareThunk,
    sectionData,
  })) {
    if (text.length === 0 || text.includes("\0")) fail(`Empty or invalid ${label} evidence.`);
  }
  const source = [context.source_artifact_id];
  const evidence = [
    {
      assignment_id: context.assignment_id,
      questions: parseQuestions(instructionsBytes.toString("utf8"), context.requirement_ids),
      observations: [
        {
          observation_id: "static-x86.observation.archive",
          kind: "artifact_identity",
          text: `Archive SHA-256 ${context.specimen.sha256}; ${specimen.byteLength} bytes; members: ${listing.join(", ")}. Extracted PE SHA-256 ${createHash("sha256").update(sample).digest("hex")}; ${sample.byteLength} bytes.`,
          artifact_ids: source,
          required: true,
        },
        {
          observation_id: "static-x86.observation.toolchain",
          kind: "analyzer_provenance",
          text: objdumpVersion.toString("utf8").split("\n", 1)[0].trim(),
          artifact_ids: source,
          required: true,
        },
        {
          observation_id: "static-x86.observation.pe-headers-imports",
          kind: "pe_headers",
          text: headers,
          artifact_ids: source,
          required: true,
        },
        {
          observation_id: "static-x86.observation.window-procedure",
          kind: "targeted_disassembly",
          text: windowProcedure,
          artifact_ids: source,
          required: true,
        },
        {
          observation_id: "static-x86.observation.compare-thunk",
          kind: "targeted_disassembly",
          text: compareThunk,
          artifact_ids: source,
          required: true,
        },
        {
          observation_id: "static-x86.observation.section-data",
          kind: "section_hex_dump",
          text: sectionData,
          artifact_ids: source,
          required: true,
        },
      ],
      check_ids: context.required_check_ids,
    },
  ];
  const encoded = Buffer.from(`${JSON.stringify(evidence)}\n`, "utf8");
  if (encoded.byteLength > 1024 * 1024) fail("Evidence output exceeds its declared bound.");
  await writeFile(OUTPUT_EVIDENCE, encoded, { flag: "wx", mode: 0o600 });
}

main().catch((error) => {
  process.stderr.write(
    `templar-course-static: ${error instanceof Error ? error.message : "unknown error"}\n`,
  );
  process.exitCode = 1;
});
