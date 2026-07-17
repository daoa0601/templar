import { mkdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import { analyzeClassicPcapFile } from "../../dist/pcap-analyzer.js";

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

await mkdir(dataDirectory, { recursive: true });

const results = [];
for (const capture of captures) {
  const filePath = await capturePath(capture);
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

process.stdout.write(`${JSON.stringify({ cases: results }, null, 2)}\n`);
