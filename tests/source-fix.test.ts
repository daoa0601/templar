import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it, vi } from "vitest";

import { decodeSourceSecurityFixInput } from "../src/contracts.js";
import { ScriptedTemplarRuntime } from "../src/fake-runtime.js";
import { TemplarService } from "../src/service.js";
import { buildSourceFixContext } from "../src/source-fix.js";
import {
  assertSourceValidationOperation,
  SOURCE_VALIDATION_MEDIA_TYPE,
} from "../src/source-validation.js";
import { buildSourceSurface, decodeSourceSnapshot } from "../src/source.js";
import { sourceSecurityFixWorkflow } from "../src/workflow.js";
import { initializeSourceSecurityFixWorkspace } from "../src/workspace.js";
import { sourceSnapshot } from "./source-fixture.js";
import { temporaryDirectory, testConfig } from "./helpers.js";

const execFileAsync = promisify(execFile);

async function evaluate(root: string): Promise<Record<string, unknown>> {
  try {
    const run = await execFileAsync("node", [path.join(root, "evaluation", "evaluate.mjs")], {
      cwd: root,
      encoding: "utf8",
    });
    return JSON.parse(run.stdout) as Record<string, unknown>;
  } catch (error) {
    const stdout =
      typeof error === "object" && error !== null && "stdout" in error
        ? String(error.stdout)
        : "{}";
    return JSON.parse(stdout) as Record<string, unknown>;
  }
}

function acceptedFinding(surface: ReturnType<typeof buildSourceSurface>) {
  const entry = surface.entry_points.find((hint) => hint.path === "src/app.ts")!;
  const input = surface.input_hints.find((hint) => hint.path === "src/app.ts")!;
  const sink = surface.sink_hints.find((hint) => hint.path === "src/app.ts")!;
  const gate = (evidence: string) => ({ passed: true, evidence });
  return {
    finding_id: "FINDING-001",
    title: "Request data reaches an unbounded file path",
    cwe: "CWE-22",
    severity: "high",
    confidence: "medium",
    primary_location: { path: "src/app.ts", line: 5 },
    entry_point_hint_ids: [entry.hint_id],
    input_hint_ids: [input.hint_id],
    sink_hint_ids: [sink.hint_id],
    data_flow: [
      { path: "src/app.ts", line: 4, description: "The route reads the request query value." },
      { path: "src/app.ts", line: 5, description: "The value is interpolated into a path." },
    ],
    gates: {
      unintended_behavior: gate("Reading outside the intended root is unintended."),
      production_reachability: gate("The route is registered in production source."),
      attacker_control: gate("The value originates from req.query.name."),
      defense_failure: gate("No normalized boundary check is visible."),
      new_capability: gate("Traversal could expose an otherwise unavailable file."),
    },
    attack: "Supply traversal segments in the query value.",
    impact: "A reachable file could be disclosed outside the intended root.",
    fix_strategy: "Resolve against a fixed root and reject paths outside it.",
  };
}

async function fixWorkspace() {
  const snapshot = decodeSourceSnapshot(sourceSnapshot());
  const surface = buildSourceSurface(snapshot);
  const context = buildSourceFixContext({
    sourceAuditRunId: "accepted-audit-run",
    sourceSnapshotId: `source_sha256_${"c".repeat(64)}`,
    snapshot,
    surface,
    auditResult: {
      schema_version: "1",
      status: "completed",
      findings: [acceptedFinding(surface)],
    },
  });
  const workspace = await initializeSourceSecurityFixWorkspace({
    templarHome: await temporaryDirectory("templar-source-fix-"),
    runId: "source-fix-workspace",
    snapshot,
    context,
  });
  return { workspace, context };
}

async function writeValidFix(
  root: string,
  context: Awaited<ReturnType<typeof fixWorkspace>>["context"],
): Promise<void> {
  const applicationPath = path.join(root, "target", "src", "app.ts");
  const application = await readFile(applicationPath, "utf8");
  await writeFile(
    applicationPath,
    application
      .replace(
        'import { readFile } from "node:fs/promises";',
        'import { readFile } from "node:fs/promises";\nimport path from "node:path";',
      )
      .replace(
        '  const data = await readFile(`/srv/files/${name}`, "utf8");',
        '  const root = "/srv/files";\n  const candidate = path.resolve(root, String(name));\n  if (!candidate.startsWith(`${root}${path.sep}`)) return res.status(400).send("invalid path");\n  const data = await readFile(candidate, "utf8");',
      ),
    "utf8",
  );
  const testPath = "tests/source-boundary.test.ts";
  await mkdir(path.join(root, "target", "tests"), { recursive: true });
  await writeFile(
    path.join(root, "target", testPath),
    'test("rejects traversal", () => expect("../secret").toContain(".."));\n',
    "utf8",
  );
  const finding = context.findings[0]!;
  const output = {
    schema_version: "1",
    status: "completed",
    summary: "The fixed-root path boundary now rejects traversal and has a focused regression.",
    finding_resolutions: [
      {
        finding_id: finding.finding_id,
        root_cause: "The route interpolated request data directly into a filesystem path.",
        changed_paths: ["src/app.ts"],
        regression_test_paths: [testPath],
        variant_locations: [
          finding.primary_location,
          ...finding.data_flow
            .slice(0, 1)
            .map((location) => ({ path: location.path, line: location.line })),
        ],
        residual_risk: "Dynamic filesystem behavior remains untested until an approved replay.",
      },
    ],
    changes: [
      {
        path: "src/app.ts",
        status: "modified",
        finding_ids: [finding.finding_id],
        rationale: "Canonicalize against the intended root and reject escaped paths.",
      },
      {
        path: testPath,
        status: "added",
        finding_ids: [finding.finding_id],
        rationale: "Preserve the boundary behavior with a regression test.",
      },
    ],
    tests: [
      {
        path: testPath,
        finding_ids: [finding.finding_id],
        expected_behavior: "Traversal input is rejected before filesystem access.",
      },
    ],
    dynamic_validation: { status: "not_run", job_id: null },
    promotion: {
      impact: context.required_promotion_impact,
      security_outcome: true,
      headline_result: false,
    },
    external_mutations: [],
  };
  await writeFile(path.join(root, "result.json"), `${JSON.stringify(output, null, 2)}\n`, "utf8");
  await writeFile(
    path.join(root, "report.md"),
    "# Fix summary\n\nA fixed-root boundary was added.\n\n# Finding coverage\n\nFINDING-001 is addressed at the sink.\n\n# Tests\n\nA traversal regression was added but not executed.\n\n# Residual risk\n\nDynamic behavior awaits an approved Drone replay.\n",
    "utf8",
  );
}

async function waitForTerminal(service: TemplarService, runId: string) {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const run = await service.inspectRun(runId);
    if (run.status !== "queued" && run.status !== "running") return run;
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("source workflow did not finish");
}

async function acceptedAuditAndFix(service: TemplarService) {
  const artifact = await service.stageSourceSnapshot(sourceSnapshot());
  const audit = await service.submitSourceSecurityAudit({
    schema_version: "1",
    source_snapshot_id: artifact.artifact_id,
  });
  await waitForTerminal(service, audit.run_id);
  const fix = await service.submitSourceSecurityFix(
    decodeSourceSecurityFixInput({ schema_version: "1", audit_run_id: audit.run_id }),
  );
  await waitForTerminal(service, fix.run_id);
  return { audit, fix };
}

function validationOperation(enabled = true) {
  return {
    operation_id: "source.validate",
    enabled,
    provider: "apple_native",
    architecture: "arm64" as const,
    network: "none" as const,
    inputs: [
      {
        name: "source",
        required: true,
        max_bytes: 16 * 1024 * 1024,
        media_types: [SOURCE_VALIDATION_MEDIA_TYPE],
      },
    ],
    outputs: [
      {
        name: "validation",
        required: true,
        max_bytes: 1024 * 1024,
        media_type: "application/json",
      },
    ],
    resources: {
      cpus: 2,
      memory_mb: 2048,
      rootfs_mb: 4096,
      writable_mb: 1024,
      output_disk_mb: 256,
      timeout_seconds: 300,
      max_log_bytes: 256 * 1024,
      max_processes: 128,
      max_open_files: 256,
    },
  };
}

describe("source security fix workflow", () => {
  it("derives immutable fix scope only from accepted structured findings", async () => {
    const snapshot = decodeSourceSnapshot(sourceSnapshot());
    const surface = buildSourceSurface(snapshot);
    const context = buildSourceFixContext({
      sourceAuditRunId: "audit-001",
      sourceSnapshotId: `source_sha256_${"a".repeat(64)}`,
      snapshot,
      surface,
      auditResult: {
        schema_version: "1",
        status: "completed",
        findings: [acceptedFinding(surface)],
      },
    });
    expect(context).toMatchObject({
      required_finding_ids: ["FINDING-001"],
      required_promotion_impact: "high",
      dynamic_validation: {
        candidate_must_report: "not_run",
        execution_boundary: "drone_registered_operation_only",
      },
    });
    expect(() =>
      buildSourceFixContext({
        sourceAuditRunId: "audit-002",
        sourceSnapshotId: `source_sha256_${"b".repeat(64)}`,
        snapshot,
        auditResult: { schema_version: "1", status: "completed", findings: [] },
      }),
    ).toThrow(/no findings/iu);
  });

  it("accepts a scoped patch with linked regressions and rejects false execution claims", async () => {
    const { workspace, context } = await fixWorkspace();
    await writeValidFix(workspace.root, context);
    const accepted = await evaluate(workspace.root);
    expect(accepted, JSON.stringify(accepted)).toMatchObject({
      passed: true,
      score: 100,
      evaluator_version: "source-fix-evaluator-v1",
    });
    const result = JSON.parse(
      await readFile(path.join(workspace.root, "result.json"), "utf8"),
    ) as Record<string, unknown>;
    result.dynamic_validation = { status: "succeeded", job_id: `job_${"a".repeat(32)}` };
    await writeFile(
      path.join(workspace.root, "result.json"),
      `${JSON.stringify(result, null, 2)}\n`,
      "utf8",
    );
    expect(JSON.stringify(await evaluate(workspace.root))).toContain(
      "false_dynamic_validation_claim",
    );
  });

  it("rejects unmanifested patch files", async () => {
    const { workspace, context } = await fixWorkspace();
    await writeValidFix(workspace.root, context);
    await writeFile(path.join(workspace.root, "target", "src", "unrelated.ts"), "export {};\n");
    expect(JSON.stringify(await evaluate(workspace.root))).toContain("missing_change_manifest");
  });

  it("declares the fixed planner, parallel candidates, pinned audits, and selection sequence", async () => {
    const { workspace } = await fixWorkspace();
    const workflow = sourceSecurityFixWorkflow(workspace);
    expect(workflow.limits).toMatchObject({
      maxRounds: 4,
      maxConcurrentAgents: 2,
      maxTotalAgents: 5,
      maxTotalAgentTurns: 5,
    });
    expect(workflow.roles.map((role) => [role.id, role.kind, role.maxInstances])).toEqual([
      ["fix_planner", "research", 1],
      ["fix_candidate", "candidate", 2],
      ["evaluation_auditor", "review", 2],
    ]);
  });

  it("runs an accepted audit into an isolated accepted fix without executing the project", async () => {
    const config = await testConfig();
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    await service.initialize();
    const { audit, fix } = await acceptedAuditAndFix(service);
    expect(await service.result(audit.run_id)).toMatchObject({
      result: { findings: [{ finding_id: "FINDING-001", severity: "high" }] },
    });
    expect(await service.inspectRun(fix.run_id)).toMatchObject({
      workflow: "source_security_fix",
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
      rounds: 4,
      agentTurns: 5,
      totalAgents: 5,
    });
    expect(await service.result(fix.run_id)).toMatchObject({
      result: {
        status: "completed",
        finding_resolutions: [{ finding_id: "FINDING-001" }],
        dynamic_validation: { status: "not_run", job_id: null },
        external_mutations: [],
      },
      evaluation: {
        strategy: "deterministic_evaluator_with_review",
        passed: true,
        review: { auditorCount: 1, traceComplete: true },
      },
      promotion: {
        reasons: ["high_impact_result", "security_result"],
        eligible: false,
      },
    });
    expect(
      await readFile(
        path.join(service.incidentDirectory(fix.run_id), "target", "src", "app.ts"),
        "utf8",
      ),
    ).toContain("Security boundary hardened for FINDING-001");
  }, 30_000);

  it("submits a separately approved content-addressed no-network Drone replay", async () => {
    const staged: Array<Uint8Array> = [];
    const operation = validationOperation();
    const artifactId = `sha256_${"d".repeat(64)}`;
    const jobId = `job_${"e".repeat(32)}`;
    let stagedArtifactId = "";
    const stageArtifact = vi.fn(async (bytes: Uint8Array, mediaType: string) => {
      expect(mediaType).toBe(SOURCE_VALIDATION_MEDIA_TYPE);
      staged.push(bytes);
      const digest = createHash("sha256").update(bytes).digest("hex");
      stagedArtifactId = `sha256_${digest}`;
      return {
        schema_version: "1" as const,
        artifact_id: stagedArtifactId,
        sha256: digest,
        size_bytes: bytes.byteLength,
        media_type: mediaType,
        created_at: "2026-07-18T10:00:00.000Z",
      };
    });
    const submitJob = vi.fn(
      async (input: { operation_id: string; inputs: Record<string, string> }) => ({
        schema_version: "1" as const,
        job_id: jobId,
        operation_id: input.operation_id,
        provider_id: "apple_native",
        status: "queued" as const,
        inputs: input.inputs,
        outputs: [],
        submitted_at: "2026-07-18T10:00:01.000Z",
      }),
    );
    const drone = {
      providers: async () => [],
      operations: async () => [operation],
      stageArtifact,
      submitJob,
      job: async () => ({
        schema_version: "1" as const,
        job_id: jobId,
        operation_id: operation.operation_id,
        provider_id: "apple_native",
        status: "succeeded" as const,
        inputs: { source: stagedArtifactId },
        outputs: [
          {
            name: "validation",
            artifact_id: artifactId,
            size_bytes: 128,
            media_type: "application/json",
          },
        ],
        submitted_at: "2026-07-18T10:00:01.000Z",
        started_at: "2026-07-18T10:00:02.000Z",
        finished_at: "2026-07-18T10:00:03.000Z",
        exit_code: 0,
        timed_out: false,
      }),
    };
    const config = await testConfig({
      droneEnabled: true,
      droneSourceValidationOperationId: operation.operation_id,
    });
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
      droneClient: drone,
    });
    await service.initialize();
    const { fix } = await acceptedAuditAndFix(service);
    await expect(
      service.submitSourceFixValidation(fix.run_id, "Run the isolated regression replay."),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    await service.acknowledgePromotion(
      fix.run_id,
      "Approve the accepted static security fix for controlled follow-up.",
    );
    const submitted = await service.submitSourceFixValidation(
      fix.run_id,
      "Run the isolated regression replay.",
    );
    expect(submitted).toMatchObject({
      request: { operation_id: "source.validate", job_id: jobId },
      job: { status: "queued" },
    });
    const bundle = JSON.parse(Buffer.from(staged[0]!).toString("utf8")) as {
      files: ReadonlyArray<{ path: string; content: string }>;
    };
    expect(bundle.files.find((file) => file.path === "src/app.ts")?.content).toContain(
      "Security boundary hardened for FINDING-001",
    );
    await expect(service.sourceFixValidation(fix.run_id)).resolves.toMatchObject({
      job: { status: "succeeded", outputs: [{ name: "validation" }] },
    });
    await service.submitSourceFixValidation(fix.run_id, "Run the isolated regression replay.");
    expect(stageArtifact).toHaveBeenCalledTimes(1);
    expect(submitJob).toHaveBeenCalledTimes(1);
  }, 30_000);

  it("rejects a disabled or incompatible Drone operation before staging", () => {
    expect(() => assertSourceValidationOperation(validationOperation(false), 1024)).toThrow(
      /no-network source-validation contract/iu,
    );
  });
});
