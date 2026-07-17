import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { decodeIncidentInput } from "../src/contracts.js";
import { analyzeClassicPcapBytes } from "../src/pcap-analyzer.js";
import { initializeTelecomIncidentWorkspace } from "../src/workspace.js";
import { classicPcap, tcpPacket, temporaryDirectory } from "./helpers.js";

const execFileAsync = promisify(execFile);

async function runEvaluator(root: string): Promise<Record<string, unknown>> {
  try {
    const output = await execFileAsync("node", [path.join(root, "evaluation", "evaluate.mjs")], {
      cwd: root,
      encoding: "utf8",
    });
    return JSON.parse(output.stdout) as Record<string, unknown>;
  } catch (error) {
    const stdout =
      typeof error === "object" && error !== null && "stdout" in error
        ? String(error.stdout)
        : "{}";
    return JSON.parse(stdout) as Record<string, unknown>;
  }
}

function candidate(rate: number): Record<string, unknown> {
  return {
    schema_version: "1",
    status: "completed",
    summary: "The packet evidence is classified by the active local policy.",
    severity: "high",
    evidence_ids: ["evidence.incident.request", "evidence.pcap.capture"],
    citations: [
      { document_id: "SOP-NET-001", section_id: "SOP-NET-001#1" },
      { document_id: "SOP-NET-001", section_id: "SOP-NET-001#2.1" },
      { document_id: "SOP-NET-001", section_id: "SOP-NET-001#2.2" },
      { document_id: "SOP-NET-001", section_id: "SOP-NET-001#3" },
    ],
    metric_claims: [
      { fact_id: "fact.tcp.retransmissions", metric: "tcp_retransmission_percent", value: rate },
      { fact_id: "fact.tcp.retransmissions", metric: "tcp_retransmissions", value: 1 },
      { fact_id: "fact.tcp.retransmissions", metric: "tcp_packets", value: 2 },
    ],
    findings: [
      {
        finding_id: "finding.tcp_retransmission_policy",
        rule_id: "POLICY-TCP-RETRANS-001",
        severity: "high",
        evidence_ids: ["evidence.pcap.capture"],
        statement: "The persisted metric crosses the high band.",
      },
    ],
    action_plan: [
      {
        ordinal: 1,
        action_id: "sop.step.2.1",
        source_rule_ids: ["POLICY-TCP-RETRANS-001"],
        prerequisites: [],
      },
      {
        ordinal: 2,
        action_id: "sop.step.2.2",
        source_rule_ids: ["POLICY-TCP-RETRANS-001"],
        prerequisites: ["sop.step.2.1"],
      },
      {
        ordinal: 3,
        action_id: "sop.step.3",
        source_rule_ids: ["POLICY-TCP-RETRANS-001"],
        prerequisites: ["sop.step.2.2"],
      },
    ],
    unknown_ids: ["unknown.interface_mapping", "unknown.port_counters", "unknown.qos_policy"],
    checks_performed: ["incident_input", "pcap_analysis"],
    evaluationAudit: {
      checks_rerun: ["deterministic_evaluator"],
      suspicious_behavior: [],
      findings: [],
      disposition: "pass",
      manualAuditRequired: false,
      trace_available: false,
    },
    promotion: { impact: "high", security_outcome: false, headline_result: false },
    external_mutations: [],
  };
}

async function preparedWorkspace(): Promise<{ readonly root: string; readonly rate: number }> {
  const templarHome = await temporaryDirectory("templar-workspace-");
  const pcap = analyzeClassicPcapBytes(
    classicPcap([
      tcpPacket({ sequence: 10, flags: 0x18, payload: "payload" }),
      tcpPacket({ sequence: 10, flags: 0x18, payload: "payload" }),
    ]),
    `pcap_sha256_${"1".repeat(64)}`,
    { maxBytes: 1024 * 1024, maxPackets: 100 },
  );
  const workspace = await initializeTelecomIncidentWorkspace({
    templarHome,
    runId: "workspace-test",
    incident: decodeIncidentInput({ schema_version: "1", request: "Investigate packet loss" }),
    pcap,
  });
  return { root: workspace.root, rate: pcap.metrics.tcp_retransmission_percent };
}

describe("incident workspace and deterministic evaluator", () => {
  it("initializes a clean committed workspace with immutable versioned inputs", async () => {
    const { root } = await preparedWorkspace();
    const status = await execFileAsync("git", ["status", "--porcelain=v1"], {
      cwd: root,
      encoding: "utf8",
    });
    expect(status.stdout).toBe("");
    expect(JSON.parse(await readFile(path.join(root, "workflow.json"), "utf8"))).toMatchObject({
      workflow_id: "telecom_incident",
    });
    expect(
      await readFile(path.join(root, "domain", "v1", "documents", "sop_packet_loss.md"), "utf8"),
    ).toContain("SOP-NET-001");
    expect(await readFile(path.join(root, "CANDIDATE_INSTRUCTIONS.md"), "utf8")).toContain(
      "iterative local check loop",
    );
  });

  it("emits a deterministic coverage score for a valid candidate", async () => {
    const { root, rate } = await preparedWorkspace();
    await writeFile(path.join(root, "result.json"), JSON.stringify(candidate(rate)), "utf8");
    await writeFile(
      path.join(root, "report.md"),
      "# Report\n\n## Audit findings\n\nDeterministic evaluator rerun.\n",
      "utf8",
    );
    const evaluation = await runEvaluator(root);
    expect(evaluation).toMatchObject({
      passed: true,
      score: 100,
      evaluator_version: "templar-evaluator-v1",
    });
  });

  it.each([
    [
      "fabricated metric",
      (value: Record<string, unknown>) => {
        const claims = value.metric_claims as Array<Record<string, unknown>>;
        claims[0]!.value = 99;
      },
      "fabricated_metric",
    ],
    [
      "wrong severity",
      (value: Record<string, unknown>) => {
        value.severity = "low";
      },
      "policy_inconsistent_severity",
    ],
    [
      "unsupported action",
      (value: Record<string, unknown>) => {
        const actions = value.action_plan as Array<Record<string, unknown>>;
        actions[0]!.action_id = "run.arbitrary.command";
      },
      "unsupported_action",
    ],
    [
      "unavailable check",
      (value: Record<string, unknown>) => {
        value.checks_performed = ["incident_input", "pcap_analysis", "jira_write"];
      },
      "unavailable_check_claim",
    ],
    [
      "missing required SOP citations",
      (value: Record<string, unknown>) => {
        value.citations = [];
      },
      "missing_required_citation",
    ],
  ])("hard-rejects %s", async (_label, mutate, expectedCode) => {
    const { root, rate } = await preparedWorkspace();
    const value = candidate(rate);
    mutate(value);
    await writeFile(path.join(root, "result.json"), JSON.stringify(value), "utf8");
    await writeFile(
      path.join(root, "report.md"),
      "# Report\n\n## Audit findings\n\nChecked.\n",
      "utf8",
    );
    const evaluation = await runEvaluator(root);
    expect(evaluation.passed).toBe(false);
    expect(JSON.stringify(evaluation.hard_gate_failures)).toContain(expectedCode);
  });
});
