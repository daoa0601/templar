import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { analyzeClassicPcapBytes } from "../src/pcap-analyzer.js";
import { buildPcapSecurityEvidence } from "../src/pcap-security.js";
import { initializePcapSecurityTriageWorkspace } from "../src/workspace.js";
import { classicPcap, tcpPacket, temporaryDirectory } from "./helpers.js";

const execFileAsync = promisify(execFile);

interface SecurityContext {
  readonly required_observation_ids: ReadonlyArray<string>;
  readonly known_principle_ids: ReadonlyArray<string>;
  readonly required_unknown_ids: ReadonlyArray<string>;
  readonly allowed_actions: ReadonlyArray<{ readonly action_id: string }>;
  readonly available_checks: ReadonlyArray<string>;
}

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

async function preparedWorkspace(): Promise<string> {
  const templarHome = await temporaryDirectory("templar-security-");
  const pcap = analyzeClassicPcapBytes(
    classicPcap([
      tcpPacket({
        sequence: 1,
        flags: 0x02,
        sourcePort: 40_000,
        destinationPort: 25,
        destination: [10, 0, 0, 2],
      }),
      tcpPacket({
        sequence: 2,
        flags: 0x02,
        sourcePort: 40_001,
        destinationPort: 3389,
        destination: [10, 0, 0, 3],
      }),
    ]),
    `pcap_sha256_${"2".repeat(64)}`,
    { maxBytes: 1024 * 1024, maxPackets: 100 },
  );
  return (
    await initializePcapSecurityTriageWorkspace({
      templarHome,
      runId: "pcap-security-test",
      pcap,
    })
  ).root;
}

async function validCandidate(root: string): Promise<Record<string, unknown>> {
  const context = JSON.parse(
    await readFile(path.join(root, "evaluation", "context.json"), "utf8"),
  ) as SecurityContext;
  return {
    schema_version: "1",
    status: "needs_review",
    summary: "The packet pattern warrants passive review with endpoint and baseline context.",
    assessment: "suspicious_needs_review",
    observation_ids: context.required_observation_ids,
    hypotheses: [
      {
        hypothesis_id: "hypothesis.unexpected_automation",
        statement: "The observed pattern may be automated or unexpected network activity.",
        confidence: "low",
        observation_ids: context.required_observation_ids.slice(0, 3),
        principle_ids: context.known_principle_ids.slice(0, 2),
        alternatives: ["approved administration", "routine service traffic"],
        unknown_ids: context.required_unknown_ids,
        kill_chain_stage: null,
      },
    ],
    unknown_ids: context.required_unknown_ids,
    advisory_action_ids: context.allowed_actions.map((action) => action.action_id),
    checks_performed: context.available_checks,
    promotion: { impact: "routine", security_outcome: true, headline_result: false },
    external_mutations: [],
  };
}

async function writeCandidate(root: string, value: Record<string, unknown>): Promise<void> {
  await writeFile(path.join(root, "result.json"), `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await writeFile(
    path.join(root, "report.md"),
    "# Observed facts\n\nBounded parser observations are referenced in result.json.\n\n# Hypotheses\n\nThe pattern needs authorized correlation and has plausible operational alternatives.\n\n# Defensive next steps\n\nPreserve and correlate the supplied evidence without changing external systems.\n",
    "utf8",
  );
}

describe("passive PCAP security triage", () => {
  it("surfaces high fan-out packet facts without assigning a security verdict", () => {
    const packets = Array.from({ length: 120 }, (_, index) =>
      tcpPacket({
        sequence: index + 1,
        flags: 0x02,
        sourcePort: 40_000 + index,
        destinationPort: 25,
        destination: [10, 0, 1, index + 1],
      }),
    );
    const pcap = analyzeClassicPcapBytes(classicPcap(packets), "pcap_sha256_test", {
      maxBytes: 1024 * 1024,
      maxPackets: 200,
    });
    const built = buildPcapSecurityEvidence(pcap);
    const sourceProfiles = built.evidence.observations.find(
      (observation) => observation.fact_id === "fact.transport.source_profiles",
    )?.value as ReadonlyArray<Record<string, number | string>>;

    expect(sourceProfiles[0]).toMatchObject({
      source: "10.0.0.1",
      unique_endpoints: 120,
      tcp_syn_without_ack_packets: 120,
    });
    expect(JSON.stringify(built.evidence)).not.toMatch(/malware|compromise|attribution/iu);
  });

  it("creates a clean fact-only workspace and scores a grounded advisory result", async () => {
    const root = await preparedWorkspace();
    const tracked = await execFileAsync("git", ["ls-files"], { cwd: root, encoding: "utf8" });
    expect(tracked.stdout).toContain("triage-playbook.json");
    expect(tracked.stdout).not.toMatch(/\.pcap|course-material|\.pdf|\.pptx/iu);
    expect(await readFile(path.join(root, "CANDIDATE_INSTRUCTIONS.md"), "utf8")).not.toContain(
      "/Users/",
    );

    await writeCandidate(root, await validCandidate(root));
    expect(await runEvaluator(root)).toMatchObject({
      passed: true,
      score: 100,
      evaluator_version: "pcap-security-evaluator-v1",
    });
  });

  it.each([
    [
      "a definitive packet-only conclusion",
      (value: Record<string, unknown>) => {
        value.summary = "Confirmed compromise from the capture.";
      },
      "unsupported_definitive_claim",
    ],
    [
      "an unknown observation",
      (value: Record<string, unknown>) => {
        value.observation_ids = ["observation.fabricated"];
      },
      "unknown_observation",
    ],
    [
      "an active action",
      (value: Record<string, unknown>) => {
        value.advisory_action_ids = ["action.scan_host"];
      },
      "unsupported_action",
    ],
    [
      "an external mutation",
      (value: Record<string, unknown>) => {
        value.external_mutations = ["blocked a destination"];
      },
      "forbidden_external_mutation",
    ],
  ])("rejects %s", async (_label, mutate, expectedCode) => {
    const root = await preparedWorkspace();
    const value = await validCandidate(root);
    mutate(value);
    await writeCandidate(root, value);
    const evaluation = await runEvaluator(root);
    expect(evaluation.passed).toBe(false);
    expect(JSON.stringify(evaluation.hard_gate_failures)).toContain(expectedCode);
  });
});
