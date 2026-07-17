import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import { analyzeClassicPcapFile } from "../../dist/pcap-analyzer.js";
import { loadConfig } from "../../dist/config.js";
import { decodePcapSecurityTriageInput } from "../../dist/contracts.js";
import { ScriptedTemplarRuntime } from "../../dist/fake-runtime.js";
import { TemplarService } from "../../dist/service.js";

const captures = [
  {
    id: "donbot",
    label: "DonBot-infected host capture",
    filename: "donbot.pcap",
    url: "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-47/botnet-capture-20110816-donbot.pcap",
  },
  {
    id: "rdp-background",
    label: "Background capture containing RDP traffic",
    filename: "rdp-background.pcap",
    url: "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-50/normal-capture-20110817.pcap",
  },
];

const dataDirectory = path.resolve(process.env.TEMPLAR_SMOKE_DIR ?? ".templar/smoke/ctu13");

async function alreadyDownloaded(filePath) {
  try {
    return (await stat(filePath)).isFile();
  } catch (error) {
    if (error !== null && typeof error === "object" && error.code === "ENOENT") return false;
    throw error;
  }
}

async function capturePath(capture) {
  const filePath = path.join(dataDirectory, capture.filename);
  if (await alreadyDownloaded(filePath)) return filePath;

  process.stderr.write(`Downloading ${capture.label}...\n`);
  const response = await fetch(capture.url);
  if (!response.ok) {
    throw new Error(`Unable to download ${capture.id}: HTTP ${response.status}.`);
  }
  await writeFile(filePath, Buffer.from(await response.arrayBuffer()));
  return filePath;
}

function factValue(analysis, factId) {
  const fact = analysis.facts.find((candidate) => candidate.fact_id === factId);
  if (fact === undefined) throw new Error(`Analyzer did not emit ${factId}.`);
  return fact.value;
}

function topFactValues(analysis, factId, limit) {
  const value = factValue(analysis, factId);
  if (!Array.isArray(value)) throw new Error(`Analyzer fact ${factId} is not a ranking.`);
  return value.slice(0, limit);
}

async function waitForTerminal(service, runId) {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const run = await service.inspectRun(runId);
    if (run.status !== "queued" && run.status !== "running") return run;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("CTU-13 harness smoke run did not finish.");
}

await mkdir(dataDirectory, { recursive: true });

const results = [];
const capturePaths = new Map();
for (const capture of captures) {
  const filePath = await capturePath(capture);
  capturePaths.set(capture.id, filePath);
  const analysis = await analyzeClassicPcapFile(filePath, `smoke:${capture.id}`, {
    maxBytes: 8 * 1024 * 1024,
    maxPackets: 30_000,
  });
  results.push({
    case: capture.id,
    label: capture.label,
    capture: factValue(analysis, "fact.capture.metadata"),
    protocols: factValue(analysis, "fact.protocol.counts"),
    top_talkers: topFactValues(analysis, "fact.ipv4.top_talkers", 5),
    destination_ports: topFactValues(analysis, "fact.transport.destination_ports", 8),
    source_profiles: topFactValues(analysis, "fact.transport.source_profiles", 8),
    transport_conversations: topFactValues(analysis, "fact.transport.conversations", 8),
    tcp: {
      ...analysis.metrics,
      flags: factValue(analysis, "fact.tcp.flags"),
    },
  });
}

let harness;
if (process.argv.includes("--harness")) {
  const donbotPath = capturePaths.get("donbot");
  if (donbotPath === undefined) throw new Error("DonBot smoke capture is unavailable.");
  const config = loadConfig({
    TEMPLAR_HOME: path.join(dataDirectory, "runtime"),
    TEMPLAR_MAX_PCAP_PACKETS: "30000",
  });
  const service = new TemplarService(config, {
    runtimeFactory: () => new ScriptedTemplarRuntime(),
  });
  await service.initialize();
  const artifact = await service.stagePcap(await readFile(donbotPath));
  const submitted = await service.submitPcapSecurityTriage(
    decodePcapSecurityTriageInput({
      schema_version: "1",
      pcap_artifact_id: artifact.artifact_id,
    }),
  );
  const run = await waitForTerminal(service, submitted.run_id);
  const output = run.status === "accepted" ? await service.result(submitted.run_id) : undefined;
  harness = {
    run_id: submitted.run_id,
    status: run.status,
    rounds: run.rounds,
    agent_turns: run.agentTurns,
    selected_candidate_id: run.selectedCandidateId ?? null,
    result: output?.result ?? null,
    evaluation: output?.evaluation ?? null,
    promotion: output?.promotion ?? null,
  };
}

process.stdout.write(
  `${JSON.stringify({ cases: results, ...(harness === undefined ? {} : { harness }) }, null, 2)}\n`,
);
