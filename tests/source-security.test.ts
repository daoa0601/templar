import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { decodeSourceSecurityAuditInput } from "../src/contracts.js";
import { ScriptedTemplarRuntime } from "../src/fake-runtime.js";
import { TemplarService } from "../src/service.js";
import { SourceSnapshotStore } from "../src/source-store.js";
import { buildSourceSurface, decodeSourceSnapshot } from "../src/source.js";
import { sourceSecurityAuditWorkflow } from "../src/workflow.js";
import { initializeSourceSecurityAuditWorkspace } from "../src/workspace.js";
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

function completeCandidate(
  surface: ReturnType<typeof buildSourceSurface>,
): Record<string, unknown> {
  return {
    schema_version: "1",
    status: "completed",
    summary: "The complete static surface was reviewed and the sample path lead was eliminated.",
    coverage: {
      scanned_file_paths: surface.files.filter((file) => file.in_scope).map((file) => file.path),
      entry_point_dispositions: surface.entry_points.map((hint) => ({
        hint_id: hint.hint_id,
        disposition: "analyzed",
        rationale: "The production entry point and its caller were inspected.",
      })),
      input_dispositions: surface.input_hints.map((hint) => ({
        hint_id: hint.hint_id,
        disposition: "attacker_controlled",
        rationale: "The value is read from a request or handler payload.",
      })),
      sink_dispositions: surface.sink_hints.map((hint) => ({
        hint_id: hint.hint_id,
        disposition: "reachable",
        rationale: "The operation is reachable, but reachability alone is not a finding.",
      })),
    },
    findings: [],
    eliminated_candidates: [
      {
        candidate_id: "CANDIDATE-001",
        title: "Path construction requires deployment context",
        reason: "The bounded snapshot does not establish the runtime path policy or impact.",
        evidence_locations: [{ path: "src/app.ts", line: 5 }],
      },
    ],
    checks_performed: surface.available_checks,
    promotion: { impact: "routine", security_outcome: true, headline_result: false },
    external_mutations: [],
  };
}

function structuredFinding(
  surface: ReturnType<typeof buildSourceSurface>,
): Record<string, unknown> {
  const entry = surface.entry_points.find((hint) => hint.path === "src/app.ts")!;
  const input = surface.input_hints.find((hint) => hint.path === "src/app.ts")!;
  const sink = surface.sink_hints.find((hint) => hint.path === "src/app.ts")!;
  const gate = (evidence: string) => ({ passed: true, evidence });
  return {
    finding_id: "FINDING-001",
    title: "Request data reaches a file path",
    cwe: "CWE-22",
    severity: "high",
    confidence: "medium",
    primary_location: { path: "src/app.ts", line: 5 },
    entry_point_hint_ids: [entry.hint_id],
    input_hint_ids: [input.hint_id],
    sink_hint_ids: [sink.hint_id],
    data_flow: [
      { path: "src/app.ts", line: 4, description: "The route reads the request query value." },
      { path: "src/app.ts", line: 5, description: "The value is interpolated into a file path." },
    ],
    gates: {
      unintended_behavior: gate("Reading outside the intended directory would not be intended."),
      production_reachability: gate("The route is registered in production source."),
      attacker_control: gate("The value originates from req.query.name."),
      defense_failure: gate("No path normalization is visible in the bounded source."),
      new_capability: gate("A successful traversal could expose an otherwise unavailable file."),
    },
    attack: "Supply traversal segments in the query value.",
    impact: "Potential disclosure depends on deployment filesystem policy.",
    fix_strategy: "Resolve against a fixed root and verify the normalized path remains inside it.",
  };
}

async function writeCandidate(
  root: string,
  surface: ReturnType<typeof buildSourceSurface>,
  mutate?: (value: Record<string, unknown>) => void,
): Promise<void> {
  const output = completeCandidate(surface);
  mutate?.(output);
  await writeFile(path.join(root, "result.json"), `${JSON.stringify(output, null, 2)}\n`, "utf8");
  await writeFile(
    path.join(root, "report.md"),
    "# Scope\n\nAll production files.\n\n# Attack surface\n\nAll indexed leads.\n\n# Confirmed findings\n\nNone.\n\n# Eliminated candidates\n\nOne bounded lead.\n\n# Limitations\n\nStatic review only.\n",
    "utf8",
  );
}

async function waitForTerminal(service: TemplarService, runId: string) {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const run = await service.inspectRun(runId);
    if (run.status !== "queued" && run.status !== "running") return run;
    await new Promise<void>((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("source security fake run did not finish");
}

describe("bounded source snapshots and security surface", () => {
  it("canonicalizes source files and rejects path ambiguity or host indirection", async () => {
    const value = sourceSnapshot();
    const decoded = decodeSourceSnapshot({ ...value, files: [...value.files].reverse() });
    expect(decoded.files.map((file) => file.path)).toEqual([
      "README.md",
      "src/app.ts",
      "src/worker.ts",
      "tests/app.test.ts",
    ]);
    for (const filePath of ["../secret.ts", "/tmp/app.ts", "src\\app.ts", ".git/config"]) {
      expect(() =>
        decodeSourceSnapshot({
          ...value,
          files: [{ path: filePath, content: "export {};" }],
        }),
      ).toThrow();
    }
    expect(() =>
      decodeSourceSnapshot({
        ...value,
        files: [
          { path: "src/App.ts", content: "a" },
          { path: "src/app.ts", content: "b" },
        ],
      }),
    ).toThrow(/case-colliding/iu);
    expect(() =>
      decodeSourceSnapshot({
        ...value,
        files: [
          { path: "src", content: "a" },
          { path: "src/app.ts", content: "b" },
        ],
      }),
    ).toThrow(/collision/iu);
  });

  it("content-addresses snapshots and builds review leads without calling them findings", async () => {
    const root = await temporaryDirectory("templar-source-store-");
    const store = new SourceSnapshotStore(root, 1024 * 1024);
    const staged = await store.stage(sourceSnapshot());
    expect(staged).toMatchObject({
      artifact_id: expect.stringMatching(/^source_sha256_[a-f0-9]{64}$/u),
      media_type: "application/vnd.templar.source-snapshot+json",
    });
    const resolved = await store.resolve(staged.artifact_id);
    const surface = buildSourceSurface(resolved);
    expect(surface.analyzer.interpretation).toBe("review_leads_not_findings");
    expect(surface.files.filter((file) => file.in_scope).map((file) => file.path)).toEqual([
      "src/app.ts",
      "src/worker.ts",
    ]);
    expect(surface.entry_points.map((hint) => hint.kind)).toEqual(
      expect.arrayContaining(["http_route", "serverless_handler"]),
    );
    expect(surface.input_hints.map((hint) => hint.kind)).toContain("http_request_field");
    expect(surface.sink_hints.map((hint) => hint.kind)).toContain("filesystem_access");
  });

  it("materializes only the snapshot and enforces complete evaluator coverage", async () => {
    const snapshot = decodeSourceSnapshot(sourceSnapshot());
    const templarHome = await temporaryDirectory("templar-source-workspace-");
    const workspace = await initializeSourceSecurityAuditWorkspace({
      templarHome,
      runId: "source-workspace-test",
      sourceSnapshotId: `source_sha256_${"a".repeat(64)}`,
      snapshot,
    });
    expect(await readFile(path.join(workspace.root, "target", "src", "app.ts"), "utf8")).toContain(
      "req.query.name",
    );
    expect(
      await readFile(path.join(workspace.root, "CANDIDATE_INSTRUCTIONS.md"), "utf8"),
    ).toContain("Lexical hints are review leads, not vulnerabilities");
    await writeCandidate(workspace.root, workspace.surface);
    expect(await evaluate(workspace.root)).toMatchObject({
      passed: true,
      score: 100,
      evaluator_version: "source-security-evaluator-v1",
    });

    await writeCandidate(workspace.root, workspace.surface, (value) => {
      const coverage = value.coverage as Record<string, unknown>;
      coverage.sink_dispositions = [];
    });
    expect(await evaluate(workspace.root)).toMatchObject({ passed: false });
    expect(JSON.stringify(await evaluate(workspace.root))).toContain("missing_surface_disposition");

    await writeCandidate(workspace.root, workspace.surface);
    await writeFile(path.join(workspace.root, "target", "src", "app.ts"), "changed\n", "utf8");
    expect(JSON.stringify(await evaluate(workspace.root))).toContain("forbidden_file_change");
  });

  it("requires all five finding gates and high-impact promotion", async () => {
    const snapshot = decodeSourceSnapshot(sourceSnapshot());
    const workspace = await initializeSourceSecurityAuditWorkspace({
      templarHome: await temporaryDirectory("templar-source-gates-"),
      runId: "source-gates-test",
      sourceSnapshotId: `source_sha256_${"d".repeat(64)}`,
      snapshot,
    });
    await writeCandidate(workspace.root, workspace.surface, (value) => {
      value.findings = [structuredFinding(workspace.surface)];
      value.promotion = { impact: "high", security_outcome: true, headline_result: false };
    });
    expect(await evaluate(workspace.root)).toMatchObject({ passed: true, score: 100 });

    await writeCandidate(workspace.root, workspace.surface, (value) => {
      const finding = structuredFinding(workspace.surface);
      const gates = finding.gates as Record<string, Record<string, unknown>>;
      gates.new_capability!.passed = false;
      value.findings = [finding];
      value.promotion = { impact: "routine", security_outcome: true, headline_result: false };
    });
    const rejected = await evaluate(workspace.root);
    expect(rejected.passed).toBe(false);
    expect(JSON.stringify(rejected)).toMatch(/unproven_finding_gate|invalid_promotion/iu);
  });

  it("declares the fixed five-round scoped-agent sequence", async () => {
    const snapshot = decodeSourceSnapshot(sourceSnapshot());
    const workspace = await initializeSourceSecurityAuditWorkspace({
      templarHome: await temporaryDirectory("templar-source-workflow-"),
      runId: "source-workflow-test",
      sourceSnapshotId: `source_sha256_${"b".repeat(64)}`,
      snapshot,
    });
    const workflow = sourceSecurityAuditWorkflow(workspace);
    expect(workflow.limits).toMatchObject({
      maxRounds: 5,
      maxConcurrentAgents: 3,
      maxTotalAgents: 8,
      maxTotalAgentTurns: 8,
    });
    expect(workflow.roles.map((role) => [role.id, role.kind, role.maxInstances])).toEqual([
      ["source_recon", "research", 1],
      ["injection_hunter", "research", 1],
      ["boundary_hunter", "research", 1],
      ["authorization_hunter", "research", 1],
      ["source_falsifier", "candidate", 2],
      ["evaluation_auditor", "review", 2],
    ]);
  });

  it("runs recon, parallel hunts, falsifiers, pinned audits, and deterministic selection", async () => {
    const config = await testConfig();
    const service = new TemplarService(config, {
      runtimeFactory: () => new ScriptedTemplarRuntime(),
    });
    await service.initialize();
    const artifact = await service.stageSourceSnapshot(sourceSnapshot());
    const submitted = await service.submitSourceSecurityAudit(
      decodeSourceSecurityAuditInput({
        schema_version: "1",
        source_snapshot_id: artifact.artifact_id,
      }),
    );
    expect(await waitForTerminal(service, submitted.run_id)).toMatchObject({
      workflow: "source_security_audit",
      status: "accepted",
      selectedCandidateId: "candidate_a",
      applied: true,
      rounds: 5,
      agentTurns: 8,
      totalAgents: 8,
    });
    expect(await service.result(submitted.run_id)).toMatchObject({
      result: {
        status: "completed",
        findings: [{ finding_id: "FINDING-001", severity: "high" }],
        external_mutations: [],
      },
      evaluation: {
        strategy: "deterministic_evaluator_with_review",
        passed: true,
        review: { auditorCount: 1, traceComplete: true },
      },
      promotion: { reasons: ["high_impact_result", "security_result"], eligible: false },
    });
  }, 20_000);
});
