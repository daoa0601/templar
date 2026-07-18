import { describe, expect, it } from "vitest";

import { gradeCourseCandidate } from "../src/course-grade.js";
import type { CourseCorpusManifest } from "../src/course-corpus.js";

const manifest: CourseCorpusManifest = {
  schema_version: "1",
  corpus_id: "fixture-course-v1",
  title: "Fixture course",
  requirement_count: 1,
  artifacts: [
    {
      artifact_id: "fixture",
      assignment_id: "fixture-assignment",
      role: "specimen",
      relative_path: "fixture.zip",
      media_type: "application/zip",
      byte_length: 1,
      sha256: "a".repeat(64),
    },
  ],
  assignments: [
    {
      assignment_id: "fixture-assignment",
      title: "Fixture",
      analysis_mode: "native_static",
      artifact_ids: ["fixture"],
      credential_ids: [],
      requirement_ids: ["fixture-assignment.q01"],
    },
  ],
};

const rubric = {
  schema_version: "1",
  corpus_id: "fixture-course-v1",
  requirements: [
    {
      requirement_id: "fixture-assignment.q01",
      minimum_criteria: 2,
      criteria: [
        { criterion_id: "behavior", target: "answer", any_of: ["creates a window"] },
        {
          criterion_id: "evidence",
          target: "observation_ids",
          any_of: ["fixture-assignment.observation.disassembly"],
        },
      ],
    },
  ],
};

function candidate(answer = "It creates a window.") {
  return {
    schema_version: "1",
    status: "completed",
    summary: "Complete fixture answer.",
    answers: [
      {
        question_id: "fixture-assignment.q01",
        answer,
        observation_ids: ["fixture-assignment.observation.disassembly"],
        uncertainty: "Runtime execution was not observed.",
      },
    ],
    unanswered_question_ids: [],
    evidence_checks_relied_on: ["targeted_disassembly"],
    checks_performed: ["deterministic_evaluator"],
    external_mutations: [],
  };
}

describe("sealed local course grade", () => {
  it("grades semantic and evidence criteria without returning answer terms", () => {
    const grade = gradeCourseCandidate({ candidate: candidate(), rubric, manifest });
    expect(grade).toMatchObject({
      passed: true,
      requirements_passed: 1,
      requirements_total: 1,
      criteria_passed: 2,
      criteria_total: 2,
      requirements: [{ failed_criterion_ids: [] }],
    });
    expect(JSON.stringify(grade)).not.toContain("creates a window");
  });

  it("reports opaque criterion failures and rejects incomplete rubric coverage", () => {
    expect(
      gradeCourseCandidate({ candidate: candidate("Unknown."), rubric, manifest }),
    ).toMatchObject({
      passed: false,
      requirements: [{ failed_criterion_ids: ["behavior"] }],
    });
    expect(() =>
      gradeCourseCandidate({
        candidate: candidate(),
        rubric: { ...rubric, requirements: [] },
        manifest,
      }),
    ).toThrow(/every corpus requirement/u);
  });
});
