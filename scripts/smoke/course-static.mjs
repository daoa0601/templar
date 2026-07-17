import { createHash } from "node:crypto";
import { execFile, spawn } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { loadConfig } from "../../dist/config.js";
import { decodeExerciseSolveInput } from "../../dist/contracts.js";
import { ScriptedTemplarRuntime } from "../../dist/fake-runtime.js";
import { TemplarService } from "../../dist/service.js";

const execFileAsync = promisify(execFile);
const realRun = process.argv.includes("--real");
const defaultCourseRoot = fileURLToPath(
  new URL("../../../../cybersec/course-material/", import.meta.url),
);
const courseRoot = path.resolve(process.env.TEMPLAR_COURSE_MATERIAL ?? defaultCourseRoot);
const archive = path.join(courseRoot, "assignments", "static-161ca8b1.zip");
const sampleMember = "static-161ca8b1.bin";
const instructionsMember = "instructions.txt";
const objdump = process.env.TEMPLAR_OBJDUMP ?? "/usr/bin/objdump";
const unzip = process.env.TEMPLAR_UNZIP ?? "/usr/bin/unzip";

async function commandText(executable, args, maximum = 1024 * 1024) {
  const run = await execFileAsync(executable, args, {
    encoding: "utf8",
    maxBuffer: maximum,
    timeout: 30_000,
  });
  return run.stdout;
}

async function sampleIdentity() {
  const child = spawn(unzip, ["-p", archive, sampleMember], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  const hash = createHash("sha256");
  let size = 0;
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  for await (const chunk of child.stdout) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > 32 * 1024 * 1024) {
      child.kill("SIGKILL");
      throw new Error("Course sample exceeds the 32 MiB smoke-test limit.");
    }
    hash.update(bytes);
  }
  const exitCode = await completion;
  if (exitCode !== 0) throw new Error(`Unable to stream course sample: ${stderr.trim()}`);
  return { digest: `sha256:${hash.digest("hex")}`, size };
}

async function analyzeSample(args, maximum = 160_000) {
  const extractor = spawn(unzip, ["-p", archive, sampleMember], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  const analyzer = spawn(objdump, [...args, "-"], {
    stdio: ["pipe", "pipe", "pipe"],
  });
  const completions = [extractor, analyzer].map(
    (child) =>
      new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("close", resolve);
      }),
  );
  let pipeError;
  analyzer.stdin.on("error", (error) => {
    if (error.code !== "EPIPE") pipeError = error;
  });
  extractor.stdout.pipe(analyzer.stdin);
  let stdout = "";
  let analyzerStderr = "";
  let extractorStderr = "";
  let exceededLimit = false;
  analyzer.stdout.setEncoding("utf8");
  analyzer.stderr.setEncoding("utf8");
  extractor.stderr.setEncoding("utf8");
  analyzer.stdout.on("data", (chunk) => {
    stdout += chunk;
    if (stdout.length > maximum) {
      exceededLimit = true;
      analyzer.kill("SIGKILL");
      extractor.kill("SIGKILL");
    }
  });
  analyzer.stderr.on("data", (chunk) => {
    analyzerStderr += chunk;
  });
  extractor.stderr.on("data", (chunk) => {
    extractorStderr += chunk;
  });
  const deadline = setTimeout(() => {
    analyzer.kill("SIGKILL");
    extractor.kill("SIGKILL");
  }, 30_000);
  const [extractorCode, analyzerCode] = await Promise.all(completions).finally(() => {
    clearTimeout(deadline);
  });
  if (extractorCode !== 0 || analyzerCode !== 0 || exceededLimit || pipeError !== undefined) {
    throw new Error(
      `Bounded static analysis failed: ${extractorStderr.trim()} ${analyzerStderr.trim()} ${pipeError?.message ?? ""}`.trim(),
    );
  }
  return stdout.trim();
}

function questions(instructions) {
  const marker = instructions.indexOf("Questions");
  if (marker < 0) throw new Error("Course instructions have no Questions section.");
  const block = instructions.slice(marker);
  const headings = [...block.matchAll(/^([1-9][0-9]*)\.\s+/gmu)];
  const parsed = headings.map((match, index) => {
    const next = headings[index + 1];
    return {
      question_id: `question.${match[1]}`,
      prompt: block.slice(match.index + match[0].length, next?.index).trim(),
    };
  });
  if (parsed.length !== 9) throw new Error(`Expected 9 course questions, found ${parsed.length}.`);
  return parsed;
}

async function snapshot() {
  await access(archive);
  const [instructions, artifact, version, headers, windowProcedure, compareThunk, data] =
    await Promise.all([
      commandText(unzip, ["-p", archive, instructionsMember]),
      sampleIdentity(),
      commandText(objdump, ["--version"], 32_000),
      analyzeSample(["-x"]),
      analyzeSample([
        "-d",
        "--x86-asm-syntax=intel",
        "--start-address=0x140001000",
        "--stop-address=0x140001280",
      ]),
      analyzeSample([
        "-d",
        "--x86-asm-syntax=intel",
        "--start-address=0x140002140",
        "--stop-address=0x140002160",
      ]),
      analyzeSample(["-s", "-j", ".rdata", "-j", ".data"]),
    ]);
  return {
    schema_version: "1",
    exercise_id: "exercise.static.161ca8b1",
    title: "Static x86-64 analysis homework",
    artifact: {
      ...artifact,
      media_type: "application/vnd.microsoft.portable-executable",
    },
    analyzer: {
      analyzer_id: "llvm_objdump",
      version: version.split("\n", 1)[0].trim(),
    },
    questions: questions(instructions),
    observations: [
      {
        observation_id: "observation.pe.headers_imports",
        kind: "pe_headers",
        text: headers,
        required: true,
      },
      {
        observation_id: "observation.window_procedure.disassembly",
        kind: "targeted_disassembly",
        text: windowProcedure,
        required: true,
      },
      {
        observation_id: "observation.compare_thunk.disassembly",
        kind: "targeted_disassembly",
        text: compareThunk,
        required: true,
      },
      {
        observation_id: "observation.rdata_data.hex",
        kind: "section_hex_dump",
        text: data,
        required: true,
      },
    ],
    available_checks: ["pe_headers", "targeted_disassembly", "section_hex_dump"],
  };
}

async function waitForTerminal(service, runId) {
  for (let attempt = 0; attempt < 1800; attempt += 1) {
    const run = await service.inspectRun(runId);
    if (run.status !== "queued" && run.status !== "running") return run;
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("Course exercise run did not finish within 30 minutes.");
}

async function optionalGrade(result) {
  const goldenPath = process.env.TEMPLAR_EXERCISE_GOLDEN;
  if (!realRun || goldenPath === undefined) return null;
  const golden = JSON.parse(await readFile(path.resolve(goldenPath), "utf8"));
  if (
    golden.schema_version !== "1" ||
    golden.exercise_id !== "exercise.static.161ca8b1" ||
    !Array.isArray(golden.questions)
  ) {
    throw new Error("The local course golden file has an invalid identity or schema.");
  }
  if (typeof result !== "object" || result === null || !Array.isArray(result.answers)) {
    throw new Error("The accepted exercise result has no answer array.");
  }
  const answers = new Map(result.answers.map((answer) => [answer.question_id, answer.answer]));
  const seen = new Set();
  const questions = golden.questions.map((question) => {
    if (
      typeof question.question_id !== "string" ||
      seen.has(question.question_id) ||
      !Array.isArray(question.required_patterns) ||
      question.required_patterns.length === 0 ||
      question.required_patterns.some(
        (pattern) => typeof pattern !== "string" || pattern.length === 0 || pattern.length > 256,
      )
    ) {
      throw new Error("The local course golden file contains an invalid question check.");
    }
    seen.add(question.question_id);
    const answer = answers.get(question.question_id) ?? "";
    const checks = question.required_patterns.map((pattern) =>
      new RegExp(pattern, "iu").test(answer),
    );
    return {
      question_id: question.question_id,
      passed: checks.every(Boolean),
      checks_passed: checks.filter(Boolean).length,
      checks_total: checks.length,
    };
  });
  if (questions.length !== 9 || seen.size !== 9) {
    throw new Error("The local course golden file must cover all 9 questions exactly once.");
  }
  return {
    passed: questions.every((question) => question.passed),
    questions_passed: questions.filter((question) => question.passed).length,
    questions_total: questions.length,
    questions,
  };
}

const exercise = await snapshot();
const config = loadConfig({
  TEMPLAR_HOME: path.resolve(
    process.env.TEMPLAR_SMOKE_DIR ??
      path.join(".templar", "smoke", "course-static", realRun ? "real" : "fake"),
  ),
  TEMPLAR_MAX_EXERCISE_SNAPSHOT_BYTES: "524288",
});
const service = new TemplarService(
  config,
  realRun ? {} : { runtimeFactory: () => new ScriptedTemplarRuntime() },
);
await service.initialize();
const artifact = await service.stageExerciseSnapshot(exercise);
const submitted = await service.submitExerciseSolve(
  decodeExerciseSolveInput({
    schema_version: "1",
    exercise_snapshot_id: artifact.artifact_id,
  }),
);
const run = await waitForTerminal(service, submitted.run_id);
const output = run.status === "accepted" ? await service.result(submitted.run_id) : null;
const grade = output === null ? null : await optionalGrade(output.result);

process.stdout.write(
  `${JSON.stringify(
    {
      mode: realRun ? "codex" : "scripted",
      exercise: {
        exercise_id: exercise.exercise_id,
        question_count: exercise.questions.length,
        observation_count: exercise.observations.length,
        artifact: exercise.artifact,
        snapshot_artifact_id: artifact.artifact_id,
      },
      run,
      result: output?.result ?? null,
      evaluation: output?.evaluation ?? null,
      grade,
    },
    null,
    2,
  )}\n`,
);
