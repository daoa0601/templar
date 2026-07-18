import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import type {
  DroneArtifactDownload,
  DroneArtifactMetadata,
  DroneJob,
  DroneJobSubmission,
  DroneProviderStatus,
  DronePublicOperation,
} from "@agentic-orch/drone-client";
import { describe, expect, it } from "vitest";

import {
  COURSE_LAB_ANALYZER_ID,
  COURSE_LAB_CONTEXT_MEDIA_TYPE,
  COURSE_LAB_EVIDENCE_MEDIA_TYPE,
  CourseLabController,
  DRONE_EXECUTION_ATTESTATION_MEDIA_TYPE,
} from "../src/course-lab.js";
import { COURSE_ASSIGNMENT_EVIDENCE_MEDIA_TYPE } from "../src/exercise.js";
import type { CourseLabDroneClient } from "../src/course-lab.js";
import type { CourseCorpusManifest } from "../src/course-corpus.js";
import { temporaryDirectory, testConfig } from "./helpers.js";

const PROVIDER_ATTESTATION_ID = `attestation.sha256.${"a".repeat(64)}`;
const SOURCE_ARTIFACT_ID = "fixture.archive";
const ASSIGNMENT_ID = "fixture-assignment";
const SPECIMEN = Buffer.from("bounded-fixture-specimen");

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function fixtureManifest(): CourseCorpusManifest {
  return {
    schema_version: "1",
    corpus_id: "fixture-course-v1",
    title: "Fixture course",
    requirement_count: 2,
    artifacts: [
      {
        artifact_id: SOURCE_ARTIFACT_ID,
        assignment_id: ASSIGNMENT_ID,
        role: "specimen",
        relative_path: "fixture/specimen.zip",
        media_type: "application/zip",
        byte_length: SPECIMEN.byteLength,
        sha256: digest(SPECIMEN),
      },
    ],
    assignments: [
      {
        assignment_id: ASSIGNMENT_ID,
        title: "Fixture assignment",
        analysis_mode: "native_static",
        artifact_ids: [SOURCE_ARTIFACT_ID],
        credential_ids: [],
        requirement_ids: ["fixture.question-one", "fixture.question-two"],
      },
    ],
  };
}

function providerStatus(overrides: Partial<DroneProviderStatus> = {}): DroneProviderStatus {
  const issuedAt = new Date();
  const expiresAt = new Date(issuedAt.valueOf() + 60 * 60 * 1000);
  return {
    provider_id: "apple_native",
    product: "Apple Containerization",
    installed: true,
    enabled: true,
    mutations_available: true,
    attested: true,
    attestation: {
      attestation_id: PROVIDER_ATTESTATION_ID,
      profile: "apple_native_no_network_vm_v1",
      key_id: `ed25519.sha256.${"b".repeat(64)}`,
      issuer: "fixture-independent-attestor",
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
    },
    reason: "ready",
    isolation: "lightweight_vm",
    guest_os: ["linux"],
    network_modes: ["none"],
    ...overrides,
  };
}

function operation(overrides: Partial<DronePublicOperation> = {}): DronePublicOperation {
  return {
    operation_id: "course.assignment.analyze",
    enabled: true,
    provider: "apple_native",
    architecture: "arm64",
    network: "none",
    inputs: [
      {
        name: "specimen",
        required: true,
        max_bytes: 1024 * 1024,
        media_types: ["application/zip"],
      },
      {
        name: "context",
        required: true,
        max_bytes: 64 * 1024,
        media_types: [COURSE_LAB_CONTEXT_MEDIA_TYPE],
      },
    ],
    outputs: [
      {
        name: "evidence",
        required: true,
        max_bytes: 64 * 1024,
        media_type: COURSE_LAB_EVIDENCE_MEDIA_TYPE,
      },
    ],
    resources: {
      cpus: 2,
      memory_mb: 2048,
      rootfs_mb: 4096,
      writable_mb: 256,
      output_disk_mb: 32,
      timeout_seconds: 120,
      max_log_bytes: 262_144,
      max_processes: 64,
      max_open_files: 256,
    },
    ...overrides,
  };
}

function assignmentEvidence(): unknown {
  return [
    {
      assignment_id: ASSIGNMENT_ID,
      questions: [
        { question_id: "fixture.question-one", prompt: "Identify the entry behavior." },
        { question_id: "fixture.question-two", prompt: "Explain the static transformation." },
      ],
      observations: [
        {
          observation_id: `${ASSIGNMENT_ID}.observation.static-summary`,
          kind: "pe_static_summary",
          text: "The bounded analyzer recorded a fixture control-flow summary.",
          artifact_ids: [SOURCE_ARTIFACT_ID],
          required: true,
        },
      ],
      check_ids: ["pe_headers", "targeted_disassembly", "section_hex_dump"],
    },
  ];
}

function executionEvidence(providerAttestationId = PROVIDER_ATTESTATION_ID): unknown {
  return {
    schema_version: "1",
    profile: "apple_native_no_network_vm_v1",
    provider_attestation_id: providerAttestationId,
    challenge: "c".repeat(64),
    container_id: `drone-${"d".repeat(24)}`,
    image_reference: `registry.example/templar/course-tools@sha256:${"e".repeat(64)}`,
    backend: "apple_containerization",
    isolation: "lightweight_vm",
    guest_os: "linux",
    network_mode: "none",
    ephemeral_vm: true,
    read_only_root: true,
    input_disk_read_only: true,
    output_disk_bounded: true,
    host_directory_sharing: false,
    socket_sharing: false,
    nested_virtualization: false,
    non_root_required: true,
    no_new_privileges: true,
    capabilities: "none",
  };
}

class FakeLabDrone implements CourseLabDroneClient {
  readonly staged = new Map<string, { readonly bytes: Buffer; readonly mediaType: string }>();
  providersValue: ReadonlyArray<DroneProviderStatus> = [providerStatus()];
  operationsValue: ReadonlyArray<DronePublicOperation> = [operation()];
  jobValue: DroneJob | undefined;
  evidenceValue: unknown = assignmentEvidence();
  executionValue: unknown = executionEvidence();

  async providers(): Promise<ReadonlyArray<DroneProviderStatus>> {
    return this.providersValue;
  }

  async operations(): Promise<ReadonlyArray<DronePublicOperation>> {
    return this.operationsValue;
  }

  async stageArtifact(bytes: Uint8Array, mediaType: string): Promise<DroneArtifactMetadata> {
    const hash = digest(bytes);
    const artifactId = `sha256_${hash}`;
    this.staged.set(artifactId, { bytes: Buffer.from(bytes), mediaType });
    return {
      schema_version: "1",
      artifact_id: artifactId,
      sha256: hash,
      size_bytes: bytes.byteLength,
      media_type: mediaType,
      created_at: new Date().toISOString(),
    };
  }

  async submitJob(input: DroneJobSubmission): Promise<DroneJob> {
    const value: DroneJob = {
      schema_version: "1",
      job_id: `job_${"f".repeat(32)}`,
      operation_id: input.operation_id,
      provider_id: "apple_native",
      provider_attestation_id: PROVIDER_ATTESTATION_ID,
      status: "queued",
      inputs: input.inputs,
      outputs: [],
      submitted_at: new Date().toISOString(),
    };
    this.jobValue = value;
    return value;
  }

  async job(jobId: string): Promise<DroneJob> {
    if (this.jobValue?.job_id !== jobId) throw new Error("unknown job");
    return this.jobValue;
  }

  async artifactContent(artifactId: string): Promise<DroneArtifactDownload> {
    const evidenceBytes = Buffer.from(`${JSON.stringify(this.evidenceValue)}\n`);
    const evidenceArtifactId = `sha256_${digest(evidenceBytes)}`;
    if (artifactId === evidenceArtifactId) {
      return { bytes: evidenceBytes, mediaType: COURSE_LAB_EVIDENCE_MEDIA_TYPE };
    }
    const executionBytes = Buffer.from(`${JSON.stringify(this.executionValue)}\n`);
    const executionArtifactId = `sha256_${digest(executionBytes)}`;
    if (artifactId === executionArtifactId) {
      return { bytes: executionBytes, mediaType: DRONE_EXECUTION_ATTESTATION_MEDIA_TYPE };
    }
    throw new Error("unknown artifact");
  }

  complete(): void {
    if (this.jobValue === undefined) throw new Error("job was not submitted");
    const evidenceBytes = Buffer.from(`${JSON.stringify(this.evidenceValue)}\n`);
    const executionBytes = Buffer.from(`${JSON.stringify(this.executionValue)}\n`);
    this.jobValue = {
      ...this.jobValue,
      status: "succeeded",
      outputs: [
        {
          name: "evidence",
          artifact_id: `sha256_${digest(evidenceBytes)}`,
          size_bytes: evidenceBytes.byteLength,
          media_type: COURSE_LAB_EVIDENCE_MEDIA_TYPE,
        },
      ],
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      exit_code: 0,
      timed_out: false,
      execution_attestation_artifact_id: `sha256_${digest(executionBytes)}`,
    };
  }
}

async function fixture(): Promise<{
  readonly root: string;
  readonly specimen: string;
  readonly drone: FakeLabDrone;
  readonly controller: CourseLabController;
}> {
  const root = await temporaryDirectory("templar-course-lab-");
  const specimen = path.join(root, "specimen.zip");
  await writeFile(specimen, SPECIMEN, { mode: 0o600 });
  const drone = new FakeLabDrone();
  const config = await testConfig({
    templarHome: path.join(root, "state"),
    droneEnabled: true,
    droneCourseLabOperationId: operation().operation_id,
  });
  const controller = new CourseLabController(config, drone, {
    manifest: async () => fixtureManifest(),
  });
  return { root, specimen, drone, controller };
}

describe("separately attested course lab", () => {
  it("binds approval, immutable inputs, the Drone job, execution evidence, and output custody", async () => {
    const { root, specimen, drone, controller } = await fixture();
    const submitted = await controller.submit({
      sourceArtifactId: SOURCE_ARTIFACT_ID,
      specimenFile: specimen,
      specimenMediaType: "application/zip",
      approvedProviderAttestationId: PROVIDER_ATTESTATION_ID,
      rationale: "Analyze this exact course specimen in the approved disposable no-network VM.",
    });
    expect(submitted).toMatchObject({
      approval: {
        assignment_id: ASSIGNMENT_ID,
        exact_source_artifact: true,
        specimen_sha256: digest(SPECIMEN),
        provider_attestation: { attestation_id: PROVIDER_ATTESTATION_ID },
      },
      job: { status: "queued", provider_attestation_id: PROVIDER_ATTESTATION_ID },
    });
    const contextArtifact = drone.staged.get(submitted.submission.context_artifact_id);
    expect(contextArtifact?.mediaType).toBe(COURSE_LAB_CONTEXT_MEDIA_TYPE);
    expect(JSON.parse(contextArtifact!.bytes.toString("utf8"))).toMatchObject({
      profile: "templar_course_assignment_lab_v1",
      assignment_id: ASSIGNMENT_ID,
      specimen: { sha256: digest(SPECIMEN), exact_source_artifact: true },
    });
    const approvalFile = path.join(
      root,
      "state",
      "course-lab",
      submitted.approval.lab_id,
      "approval.json",
    );
    expect((await stat(approvalFile)).mode & 0o077).toBe(0);
    expect(await readFile(approvalFile, "utf8")).not.toContain(specimen);

    drone.complete();
    const destination = path.join(root, "assignment-evidence.json");
    const collected = await controller.collect(submitted.approval.lab_id, destination);
    expect(collected).toMatchObject({
      assignment_id: ASSIGNMENT_ID,
      provider_attestation_id: PROVIDER_ATTESTATION_ID,
    });
    expect(JSON.parse(await readFile(destination, "utf8"))).toEqual(assignmentEvidence());
    const snapshot = await controller.exerciseSnapshot(submitted.approval.lab_id);
    expect(snapshot).toMatchObject({
      exercise_id: `course-assignment.fixture-course-v1.${ASSIGNMENT_ID}`,
      artifact: {
        media_type: COURSE_ASSIGNMENT_EVIDENCE_MEDIA_TYPE,
      },
      analyzer: { analyzer_id: COURSE_LAB_ANALYZER_ID },
      observations: [
        { observation_id: `${ASSIGNMENT_ID}.observation.static-summary` },
        {
          observation_id: `${ASSIGNMENT_ID}.observation.execution-provenance`,
          kind: "execution_attestation",
          required: true,
        },
      ],
    });
    expect(snapshot.questions).toEqual(
      expect.arrayContaining([expect.objectContaining({ question_id: "fixture.question-one" })]),
    );
    await expect(controller.status(submitted.approval.lab_id)).resolves.toMatchObject({
      job: { status: "succeeded", execution_attestation_artifact_id: expect.any(String) },
    });
  });

  it("rejects a stale or different attestation before staging any specimen", async () => {
    const { specimen, drone, controller } = await fixture();
    await expect(
      controller.submit({
        sourceArtifactId: SOURCE_ARTIFACT_ID,
        specimenFile: specimen,
        specimenMediaType: "application/zip",
        approvedProviderAttestationId: `attestation.sha256.${"9".repeat(64)}`,
        rationale: "Approve only the explicitly reviewed no-network provider measurement.",
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(drone.staged.size).toBe(0);

    const expired = providerStatus();
    drone.providersValue = [
      {
        ...expired,
        attestation: {
          ...expired.attestation!,
          issued_at: "2026-01-01T00:00:00.000Z",
          expires_at: "2026-01-02T00:00:00.000Z",
        },
      },
    ];
    await expect(
      controller.submit({
        sourceArtifactId: SOURCE_ARTIFACT_ID,
        specimenFile: specimen,
        specimenMediaType: "application/zip",
        approvedProviderAttestationId: PROVIDER_ATTESTATION_ID,
        rationale: "Reject this request because its provider statement is no longer current.",
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(drone.staged.size).toBe(0);
  });

  it("rejects an operation that widens the fixed course-lab exchange contract", async () => {
    const { specimen, drone, controller } = await fixture();
    drone.operationsValue = [
      operation({
        inputs: [
          ...operation().inputs,
          {
            name: "host",
            required: false,
            max_bytes: 1024,
            media_types: ["text/plain"],
          },
        ],
      }),
    ];
    await expect(
      controller.submit({
        sourceArtifactId: SOURCE_ARTIFACT_ID,
        specimenFile: specimen,
        specimenMediaType: "application/zip",
        approvedProviderAttestationId: PROVIDER_ATTESTATION_ID,
        rationale: "Use only the strict two-input no-network course analyzer contract.",
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(drone.staged.size).toBe(0);
  });

  it("refuses evidence or execution custody that leaves the approved assignment boundary", async () => {
    const { root, specimen, drone, controller } = await fixture();
    const submitted = await controller.submit({
      sourceArtifactId: SOURCE_ARTIFACT_ID,
      specimenFile: specimen,
      specimenMediaType: "application/zip",
      approvedProviderAttestationId: PROVIDER_ATTESTATION_ID,
      rationale: "Collect only evidence bound to this assignment and provider measurement.",
    });
    drone.evidenceValue = [
      {
        ...(assignmentEvidence() as Array<Record<string, unknown>>)[0],
        assignment_id: "another-assignment",
      },
    ];
    drone.complete();
    await expect(
      controller.collect(submitted.approval.lab_id, path.join(root, "wrong-evidence.json")),
    ).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE" });

    drone.evidenceValue = assignmentEvidence();
    drone.executionValue = executionEvidence(`attestation.sha256.${"8".repeat(64)}`);
    drone.complete();
    await expect(
      controller.collect(submitted.approval.lab_id, path.join(root, "wrong-execution.json")),
    ).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE" });
  });
});
