import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import path from "node:path";

import { Schema, SchemaParser } from "effect";

import { domainRoot } from "./corpus.js";
import { invalidInput } from "./errors.js";

export const COURSE_CORPUS_ID = "aalto-cs-e433001-2025-v1";
export const COURSE_REQUIREMENT_COUNT = 33;

const ArtifactSchema = Schema.Struct({
  artifact_id: Schema.String,
  assignment_id: Schema.String,
  role: Schema.Literals(["specimen", "instructions", "specimen_and_instructions"]),
  relative_path: Schema.String,
  media_type: Schema.Literals([
    "application/zip",
    "application/x-7z-compressed",
    "application/pdf",
  ]),
  byte_length: Schema.Number,
  sha256: Schema.String,
});

const AssignmentSchema = Schema.Struct({
  assignment_id: Schema.String,
  title: Schema.String,
  analysis_mode: Schema.Literals([
    "windows_forensics",
    "native_static",
    "native_dynamic_semantics",
    "dotnet_reverse_engineering",
    "dotnet_batch",
  ]),
  artifact_ids: Schema.Array(Schema.String),
  credential_ids: Schema.Array(Schema.String),
  requirement_ids: Schema.Array(Schema.String),
});

const ManifestSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  corpus_id: Schema.String,
  title: Schema.String,
  requirement_count: Schema.Number,
  artifacts: Schema.Array(ArtifactSchema),
  assignments: Schema.Array(AssignmentSchema),
});

const decodeManifestShape = SchemaParser.decodeUnknownSync(ManifestSchema, {
  errors: "all",
  onExcessProperty: "error",
});

const SAFE_ID = /^[a-z][a-z0-9_.-]{0,127}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;

export type CourseArtifactRole = "specimen" | "instructions" | "specimen_and_instructions";
export type CourseAnalysisMode =
  | "windows_forensics"
  | "native_static"
  | "native_dynamic_semantics"
  | "dotnet_reverse_engineering"
  | "dotnet_batch";

export interface CourseCorpusArtifact {
  readonly artifact_id: string;
  readonly assignment_id: string;
  readonly role: CourseArtifactRole;
  readonly relative_path: string;
  readonly media_type: "application/zip" | "application/x-7z-compressed" | "application/pdf";
  readonly byte_length: number;
  readonly sha256: string;
}

export interface CourseCorpusAssignment {
  readonly assignment_id: string;
  readonly title: string;
  readonly analysis_mode: CourseAnalysisMode;
  readonly artifact_ids: ReadonlyArray<string>;
  readonly credential_ids: ReadonlyArray<string>;
  readonly requirement_ids: ReadonlyArray<string>;
}

export interface CourseCorpusManifest {
  readonly schema_version: "1";
  readonly corpus_id: string;
  readonly title: string;
  readonly requirement_count: number;
  readonly artifacts: ReadonlyArray<CourseCorpusArtifact>;
  readonly assignments: ReadonlyArray<CourseCorpusAssignment>;
}

export type CourseArtifactStatus =
  "verified" | "missing" | "not_regular_file" | "size_mismatch" | "digest_mismatch" | "unreadable";

export interface CourseArtifactInventory {
  readonly artifact_id: string;
  readonly assignment_id: string;
  readonly path: string;
  readonly status: CourseArtifactStatus;
  readonly expected_byte_length: number;
  readonly actual_byte_length: number | null;
  readonly expected_sha256: string;
  readonly actual_sha256: string | null;
}

export interface CourseCorpusInventory {
  readonly schema_version: "1";
  readonly corpus_id: string;
  readonly course_root: string;
  readonly assignment_count: number;
  readonly requirement_count: number;
  readonly verified_artifact_count: number;
  readonly complete: boolean;
  readonly artifacts: ReadonlyArray<CourseArtifactInventory>;
}

function requiredText(value: string, label: string, maximum = 512): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > maximum ||
    normalized.includes(String.fromCharCode(0))
  ) {
    throw invalidInput(`${label} is invalid.`);
  }
  return normalized;
}

function safeId(value: string, label: string): string {
  const normalized = requiredText(value, label, 128);
  if (!SAFE_ID.test(normalized)) throw invalidInput(`${label} is invalid.`);
  return normalized;
}

function unique(values: ReadonlyArray<string>, label: string): void {
  if (new Set(values).size !== values.length) throw invalidInput(`${label} contains duplicates.`);
}

function safeRelativePath(value: string, label: string): string {
  const candidate = requiredText(value, label, 2048);
  if (path.isAbsolute(candidate) || /^[a-z]:/iu.test(candidate)) {
    throw invalidInput(`${label} must be relative.`);
  }
  const segments = candidate.replaceAll("\\", "/").split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw invalidInput(`${label} contains an unsafe segment.`);
  }
  return candidate;
}

export function decodeCourseCorpusManifest(value: unknown): CourseCorpusManifest {
  let input: typeof ManifestSchema.Type;
  try {
    input = decodeManifestShape(value);
  } catch (cause) {
    throw invalidInput("Course corpus manifest v1 does not match the strict schema.", cause);
  }
  if (!Number.isSafeInteger(input.requirement_count) || input.requirement_count <= 0) {
    throw invalidInput("requirement_count must be a positive integer.");
  }
  if (input.artifacts.length === 0 || input.assignments.length === 0) {
    throw invalidInput("The course corpus must contain artifacts and assignments.");
  }

  const artifacts = input.artifacts.map((artifact, index) => {
    if (!Number.isSafeInteger(artifact.byte_length) || artifact.byte_length <= 0) {
      throw invalidInput(`artifacts[${index}].byte_length must be a positive integer.`);
    }
    if (!SHA256.test(artifact.sha256)) {
      throw invalidInput(`artifacts[${index}].sha256 is invalid.`);
    }
    return {
      artifact_id: safeId(artifact.artifact_id, `artifacts[${index}].artifact_id`),
      assignment_id: safeId(artifact.assignment_id, `artifacts[${index}].assignment_id`),
      role: artifact.role,
      relative_path: safeRelativePath(artifact.relative_path, `artifacts[${index}].relative_path`),
      media_type: artifact.media_type,
      byte_length: artifact.byte_length,
      sha256: artifact.sha256,
    } satisfies CourseCorpusArtifact;
  });
  unique(
    artifacts.map((artifact) => artifact.artifact_id),
    "artifact IDs",
  );
  unique(
    artifacts.map((artifact) => artifact.relative_path),
    "artifact paths",
  );
  const artifactIds = new Set(artifacts.map((artifact) => artifact.artifact_id));

  const assignments = input.assignments.map((assignment, index) => {
    const assignmentId = safeId(assignment.assignment_id, `assignments[${index}].assignment_id`);
    const artifactReferences = assignment.artifact_ids.map((id, referenceIndex) =>
      safeId(id, `assignments[${index}].artifact_ids[${referenceIndex}]`),
    );
    const credentialIds = assignment.credential_ids.map((id, credentialIndex) =>
      safeId(id, `assignments[${index}].credential_ids[${credentialIndex}]`),
    );
    const requirementIds = assignment.requirement_ids.map((id, requirementIndex) =>
      safeId(id, `assignments[${index}].requirement_ids[${requirementIndex}]`),
    );
    if (artifactReferences.length === 0 || requirementIds.length === 0) {
      throw invalidInput(`assignments[${index}] must reference artifacts and requirements.`);
    }
    unique(artifactReferences, `assignments[${index}].artifact_ids`);
    unique(credentialIds, `assignments[${index}].credential_ids`);
    unique(requirementIds, `assignments[${index}].requirement_ids`);
    for (const artifactId of artifactReferences) {
      if (!artifactIds.has(artifactId)) {
        throw invalidInput(`Assignment ${assignmentId} references unknown artifact ${artifactId}.`);
      }
      const artifact = artifacts.find((candidate) => candidate.artifact_id === artifactId)!;
      if (artifact.assignment_id !== assignmentId) {
        throw invalidInput(`Artifact ${artifactId} is owned by a different assignment.`);
      }
    }
    return {
      assignment_id: assignmentId,
      title: requiredText(assignment.title, `assignments[${index}].title`, 256),
      analysis_mode: assignment.analysis_mode,
      artifact_ids: artifactReferences,
      credential_ids: credentialIds,
      requirement_ids: requirementIds,
    } satisfies CourseCorpusAssignment;
  });
  unique(
    assignments.map((assignment) => assignment.assignment_id),
    "assignment IDs",
  );
  const requirementIds = assignments.flatMap((assignment) => assignment.requirement_ids);
  unique(requirementIds, "course requirement IDs");
  if (requirementIds.length !== input.requirement_count) {
    throw invalidInput("requirement_count does not match the declared requirement IDs.");
  }
  const assignmentIds = new Set(assignments.map((assignment) => assignment.assignment_id));
  for (const artifact of artifacts) {
    if (!assignmentIds.has(artifact.assignment_id)) {
      throw invalidInput(`Artifact ${artifact.artifact_id} has no owning assignment.`);
    }
  }

  return {
    schema_version: "1",
    corpus_id: safeId(input.corpus_id, "corpus_id"),
    title: requiredText(input.title, "title", 256),
    requirement_count: input.requirement_count,
    artifacts,
    assignments,
  };
}

export async function loadCourseCorpusManifest(
  manifestPath = path.join(domainRoot(), "course-corpus-manifest.json"),
): Promise<CourseCorpusManifest> {
  const manifest = decodeCourseCorpusManifest(JSON.parse(await readFile(manifestPath, "utf8")));
  if (manifest.corpus_id !== COURSE_CORPUS_ID) {
    throw invalidInput(`Expected course corpus ${COURSE_CORPUS_ID}.`);
  }
  if (manifest.requirement_count !== COURSE_REQUIREMENT_COUNT) {
    throw invalidInput(`Expected ${COURSE_REQUIREMENT_COUNT} course requirements.`);
  }
  return manifest;
}

async function hashOpenFile(file: Awaited<ReturnType<typeof open>>): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of file.createReadStream({ autoClose: false })) hash.update(chunk);
  return hash.digest("hex");
}

async function inventoryArtifact(
  courseRoot: string,
  artifact: CourseCorpusArtifact,
): Promise<CourseArtifactInventory> {
  const artifactPath = path.resolve(courseRoot, artifact.relative_path);
  const relative = path.relative(courseRoot, artifactPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw invalidInput(`Artifact ${artifact.artifact_id} escapes the course root.`);
  }
  const base = {
    artifact_id: artifact.artifact_id,
    assignment_id: artifact.assignment_id,
    path: artifactPath,
    expected_byte_length: artifact.byte_length,
    expected_sha256: artifact.sha256,
  } as const;

  let entry;
  try {
    entry = await lstat(artifactPath);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        ...base,
        status: "missing",
        actual_byte_length: null,
        actual_sha256: null,
      };
    }
    return {
      ...base,
      status: "unreadable",
      actual_byte_length: null,
      actual_sha256: null,
    };
  }
  if (!entry.isFile() || entry.isSymbolicLink()) {
    return {
      ...base,
      status: "not_regular_file",
      actual_byte_length: entry.size,
      actual_sha256: null,
    };
  }
  if (entry.size !== artifact.byte_length) {
    return {
      ...base,
      status: "size_mismatch",
      actual_byte_length: entry.size,
      actual_sha256: null,
    };
  }

  let file;
  try {
    file = await open(artifactPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = await file.stat();
    if (!opened.isFile() || opened.size !== entry.size) {
      return {
        ...base,
        status: "not_regular_file",
        actual_byte_length: opened.size,
        actual_sha256: null,
      };
    }
    const digest = await hashOpenFile(file);
    return {
      ...base,
      status: digest === artifact.sha256 ? "verified" : "digest_mismatch",
      actual_byte_length: opened.size,
      actual_sha256: digest,
    };
  } catch {
    return {
      ...base,
      status: "unreadable",
      actual_byte_length: entry.size,
      actual_sha256: null,
    };
  } finally {
    await file?.close();
  }
}

/** Verify the exact local course inputs before any parsing or agent work begins. */
export async function inventoryCourseCorpus(
  courseRootInput: string,
  manifestInput?: CourseCorpusManifest,
): Promise<CourseCorpusInventory> {
  const manifest = manifestInput ?? (await loadCourseCorpusManifest());
  const courseRoot = path.resolve(requiredText(courseRootInput, "course root", 4096));
  const artifacts = await Promise.all(
    manifest.artifacts.map((artifact) => inventoryArtifact(courseRoot, artifact)),
  );
  const verifiedArtifactCount = artifacts.filter(
    (artifact) => artifact.status === "verified",
  ).length;
  return {
    schema_version: "1",
    corpus_id: manifest.corpus_id,
    course_root: courseRoot,
    assignment_count: manifest.assignments.length,
    requirement_count: manifest.requirement_count,
    verified_artifact_count: verifiedArtifactCount,
    complete: verifiedArtifactCount === artifacts.length,
    artifacts,
  };
}
