import { describe, expect, it } from "vitest";

import {
  assertCourseExerciseSnapshot,
  buildCourseExerciseSnapshot,
  courseCorpusIdentity,
} from "../src/course-evidence.js";
import type { CourseCorpusInventory, CourseCorpusManifest } from "../src/course-corpus.js";

const manifest: CourseCorpusManifest = {
  schema_version: "1",
  corpus_id: "fixture-course-v1",
  title: "Fixture course",
  requirement_count: 1,
  artifacts: [
    {
      artifact_id: "fixture-archive",
      assignment_id: "fixture-assignment",
      role: "specimen",
      relative_path: "fixture.zip",
      media_type: "application/zip",
      byte_length: 7,
      sha256: "a".repeat(64),
    },
  ],
  assignments: [
    {
      assignment_id: "fixture-assignment",
      title: "Fixture",
      analysis_mode: "native_static",
      artifact_ids: ["fixture-archive"],
      credential_ids: [],
      requirement_ids: ["fixture-assignment.q01"],
    },
  ],
};

const inventory: CourseCorpusInventory = {
  schema_version: "1",
  corpus_id: "fixture-course-v1",
  course_root: "/not-materialized",
  assignment_count: 1,
  requirement_count: 1,
  verified_artifact_count: 1,
  complete: true,
  artifacts: [
    {
      artifact_id: "fixture-archive",
      assignment_id: "fixture-assignment",
      path: "/not-materialized/fixture.zip",
      status: "verified",
      expected_byte_length: 7,
      actual_byte_length: 7,
      expected_sha256: "a".repeat(64),
      actual_sha256: "a".repeat(64),
    },
  ],
};

function build(observationText = "bounded analyzer output") {
  return buildCourseExerciseSnapshot({
    manifest,
    inventory,
    assignments: [
      {
        assignment_id: "fixture-assignment",
        questions: [{ question_id: "fixture-assignment.q01", prompt: "What happened?" }],
        observations: [
          {
            observation_id: "fixture-assignment.observation.disassembly",
            kind: "targeted_disassembly",
            text: observationText,
            artifact_ids: ["fixture-archive"],
            required: true,
          },
        ],
        check_ids: ["pe_headers", "targeted_disassembly", "section_hex_dump"],
      },
    ],
  });
}

describe("course evidence composition", () => {
  it("builds a path-free, content-identified generic exercise snapshot", () => {
    const snapshot = build();
    expect(snapshot).toMatchObject({
      exercise_id: "course.fixture-course-v1",
      artifact: {
        ...courseCorpusIdentity(manifest),
        media_type: "application/vnd.templar.course-corpus+json",
      },
      analyzer: { analyzer_id: "templar_course_corpus", version: "1.1.0" },
    });
    expect(snapshot.observations[0]?.text).toContain("fixture-archive");
    expect(snapshot.observations[0]?.text).not.toContain(inventory.course_root);
    expect(() => assertCourseExerciseSnapshot(snapshot, manifest)).not.toThrow();
  });

  it("segments long line-oriented observations into portable citable records", () => {
    const snapshot = build(
      Array.from(
        { length: 60 },
        (_, index) => `${String(index).padStart(2, "0")},${"a".repeat(70)}`,
      ).join("\n"),
    );
    expect(snapshot.observations.length).toBeGreaterThan(1);
    expect(
      snapshot.observations.every(
        ({ observation_id, text }) =>
          observation_id.startsWith("fixture-assignment.observation.disassembly.part-") &&
          text.length < 2_100,
      ),
    ).toBe(true);
    expect(() => assertCourseExerciseSnapshot(snapshot, manifest)).not.toThrow();
  });

  it("rejects missing requirements, incomplete checks, and foreign provenance", () => {
    const base = {
      manifest,
      inventory,
      assignments: [
        {
          assignment_id: "fixture-assignment",
          questions: [{ question_id: "wrong.q01", prompt: "Wrong" }],
          observations: [
            {
              observation_id: "fixture-assignment.observation.one",
              kind: "targeted_disassembly",
              text: "bounded",
              artifact_ids: ["fixture-archive"],
              required: true,
            },
          ],
          check_ids: ["pe_headers", "targeted_disassembly", "section_hex_dump"],
        },
      ],
    } as const;
    expect(() => buildCourseExerciseSnapshot(base)).toThrow(/do not match/u);
    expect(() =>
      buildCourseExerciseSnapshot({
        ...base,
        assignments: [
          {
            ...base.assignments[0],
            questions: [{ question_id: "fixture-assignment.q01", prompt: "Question" }],
            check_ids: ["pe_headers"],
          },
        ],
      }),
    ).toThrow(/complete passive check set/u);
    expect(() =>
      buildCourseExerciseSnapshot({
        ...base,
        assignments: [
          {
            ...base.assignments[0],
            questions: [{ question_id: "fixture-assignment.q01", prompt: "Question" }],
            observations: [{ ...base.assignments[0].observations[0], artifact_ids: ["foreign"] }],
          },
        ],
      }),
    ).toThrow(/unknown assignment artifact/u);
  });
});
