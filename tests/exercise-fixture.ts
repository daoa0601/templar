import type { ExerciseSnapshot } from "../src/exercise.js";

export function exerciseSnapshot(): ExerciseSnapshot {
  return {
    schema_version: "1",
    exercise_id: "exercise.static.fixture",
    title: "Static PE fixture",
    artifact: {
      digest: `sha256:${"a".repeat(64)}`,
      size: 4096,
      media_type: "application/vnd.microsoft.portable-executable",
    },
    analyzer: {
      analyzer_id: "llvm_objdump",
      version: "LLVM fixture 1",
    },
    questions: [
      { question_id: "question.1", prompt: "What behavior is visible?" },
      { question_id: "question.2", prompt: "What value is compared?" },
    ],
    observations: [
      {
        observation_id: "observation.pe.headers",
        kind: "pe_headers",
        text: "PE32+ x86-64 GUI executable with USER32 imports.",
        required: true,
      },
      {
        observation_id: "observation.target.disassembly",
        kind: "targeted_disassembly",
        text: "140001000: mov eax, 0x31\n140001005: call CreateWindowExW",
        required: true,
      },
    ],
    available_checks: ["pe_headers", "targeted_disassembly"],
  };
}
