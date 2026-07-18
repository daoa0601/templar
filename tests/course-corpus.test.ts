import { createHash } from "node:crypto";
import { mkdir, symlink, writeFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  COURSE_CORPUS_ID,
  COURSE_REQUIREMENT_COUNT,
  decodeCourseCorpusManifest,
  inventoryCourseCorpus,
  loadCourseCorpusManifest,
} from "../src/course-corpus.js";
import { temporaryDirectory } from "./helpers.js";

function digest(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function manifest(bytes = Buffer.from("fixture")) {
  return decodeCourseCorpusManifest({
    schema_version: "1",
    corpus_id: "fixture-course-v1",
    title: "Fixture course",
    requirement_count: 1,
    artifacts: [
      {
        artifact_id: "fixture-archive",
        assignment_id: "fixture-assignment",
        role: "specimen_and_instructions",
        relative_path: "assignments/fixture.zip",
        media_type: "application/zip",
        byte_length: bytes.length,
        sha256: digest(bytes),
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
  });
}

describe("versioned course corpus", () => {
  it("loads the five-assignment, 33-requirement acceptance contract", async () => {
    const loaded = await loadCourseCorpusManifest();
    expect(loaded.corpus_id).toBe(COURSE_CORPUS_ID);
    expect(loaded.assignments).toHaveLength(5);
    expect(loaded.requirement_count).toBe(COURSE_REQUIREMENT_COUNT);
    expect(loaded.assignments.flatMap((assignment) => assignment.requirement_ids)).toHaveLength(33);
  });

  it("inventories verified bytes and fails closed on replacement", async () => {
    const root = await temporaryDirectory("templar-course-");
    const directory = path.join(root, "assignments");
    await mkdir(directory);
    const artifactPath = path.join(directory, "fixture.zip");
    await writeFile(artifactPath, "fixture");
    await expect(inventoryCourseCorpus(root, manifest())).resolves.toMatchObject({
      complete: true,
      verified_artifact_count: 1,
      artifacts: [{ status: "verified" }],
    });

    await writeFile(artifactPath, "changed");
    await expect(inventoryCourseCorpus(root, manifest())).resolves.toMatchObject({
      complete: false,
      artifacts: [{ status: "digest_mismatch" }],
    });
  });

  it("rejects symlinks and reports missing files without following them", async () => {
    const root = await temporaryDirectory("templar-course-links-");
    const directory = path.join(root, "assignments");
    await mkdir(directory);
    await symlink("/dev/null", path.join(directory, "fixture.zip"));
    await expect(inventoryCourseCorpus(root, manifest())).resolves.toMatchObject({
      complete: false,
      artifacts: [{ status: "not_regular_file" }],
    });
    await expect(
      inventoryCourseCorpus(path.join(root, "missing"), manifest()),
    ).resolves.toMatchObject({ artifacts: [{ status: "missing" }] });
  });

  it("rejects duplicate requirements, unsafe paths, and unknown artifact references", () => {
    const valid = manifest();
    expect(() =>
      decodeCourseCorpusManifest({
        ...valid,
        requirement_count: 2,
        assignments: [{ ...valid.assignments[0], requirement_ids: ["fixture.q01", "fixture.q01"] }],
      }),
    ).toThrow(/contains duplicates/u);
    expect(() =>
      decodeCourseCorpusManifest({
        ...valid,
        artifacts: [{ ...valid.artifacts[0], relative_path: "../fixture.zip" }],
      }),
    ).toThrow(/unsafe segment/u);
    expect(() =>
      decodeCourseCorpusManifest({
        ...valid,
        assignments: [{ ...valid.assignments[0], artifact_ids: ["missing-artifact"] }],
      }),
    ).toThrow(/unknown artifact/u);
  });
});
