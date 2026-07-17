import { readFile, stat } from "node:fs/promises";

import { ANALYZER_VERSION } from "./corpus.js";
import { TemplarError } from "./errors.js";
import { inspectClassicPcapHeader, readPcapUInt32 } from "./pcap-format.js";

export interface PcapFact {
  readonly fact_id: string;
  readonly kind: string;
  readonly value: unknown;
}

export interface PcapAnalysis {
  readonly schema_version: "1";
  readonly analyzer_version: typeof ANALYZER_VERSION;
  readonly artifact_id: string;
  readonly facts: ReadonlyArray<PcapFact>;
  readonly metrics: {
    readonly tcp_retransmission_percent: number;
    readonly tcp_retransmissions: number;
    readonly tcp_packets: number;
  };
}

export interface PcapAnalysisLimits {
  readonly maxBytes: number;
  readonly maxPackets: number;
}

interface TcpRetransmission {
  readonly packet: number;
  readonly flow: string;
  readonly sequence: number;
  readonly consumed: number;
}

function invalid(message: string): TemplarError {
  return new TemplarError({ code: "PCAP_INVALID", message, status: 400 });
}

function limited(message: string): TemplarError {
  return new TemplarError({ code: "PCAP_LIMIT_EXCEEDED", message, status: 400 });
}

function ipv4Address(packet: Buffer, offset: number): string {
  return `${packet[offset]}.${packet[offset + 1]}.${packet[offset + 2]}.${packet[offset + 3]}`;
}

function increment(map: Map<string, number>, key: string, amount = 1): void {
  map.set(key, (map.get(key) ?? 0) + amount);
}

function ranked(
  map: Map<string, number>,
): ReadonlyArray<{ readonly key: string; readonly packets: number }> {
  return [...map.entries()]
    .map(([key, packets]) => ({ key, packets }))
    .sort((left, right) => right.packets - left.packets || left.key.localeCompare(right.key))
    .slice(0, 10);
}

function percentage(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : Math.round((numerator / denominator) * 100_000_000) / 1_000_000;
}

export function analyzeClassicPcapBytes(
  input: Uint8Array,
  artifactId: string,
  limits: PcapAnalysisLimits,
): PcapAnalysis {
  if (input.byteLength > limits.maxBytes)
    throw limited(`PCAP exceeds the ${limits.maxBytes}-byte analysis limit.`);
  const header = inspectClassicPcapHeader(input);
  const buffer = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const protocols = { ethernet: 0, ipv4: 0, ipv6: 0, arp: 0, tcp: 0, udp: 0, icmp: 0, other: 0 };
  const talkers = new Map<string, number>();
  const conversations = new Map<string, number>();
  const seenTcpRanges = new Set<string>();
  const retransmissions: Array<TcpRetransmission> = [];
  let tcpRst = 0;
  let tcpZeroWindow = 0;
  let dnsQueries = 0;
  let dnsResponses = 0;
  let packetCount = 0;
  let capturedBytes = 0;
  let originalBytes = 0;
  let firstTimestamp: number | undefined;
  let lastTimestamp: number | undefined;
  let offset = 24;

  while (offset < buffer.byteLength) {
    if (packetCount >= limits.maxPackets)
      throw limited(`PCAP exceeds the ${limits.maxPackets}-packet analysis limit.`);
    if (buffer.byteLength - offset < 16) throw invalid("PCAP packet record header is truncated.");
    const timestampSeconds = readPcapUInt32(buffer, offset, header.byteOrder);
    const timestampFraction = readPcapUInt32(buffer, offset + 4, header.byteOrder);
    const includedLength = readPcapUInt32(buffer, offset + 8, header.byteOrder);
    const originalLength = readPcapUInt32(buffer, offset + 12, header.byteOrder);
    if (includedLength > header.snaplen)
      throw invalid("PCAP packet length exceeds the global snaplen.");
    if (includedLength > limits.maxBytes || offset + 16 + includedLength > buffer.byteLength) {
      throw invalid("PCAP packet data is truncated or exceeds the configured byte bound.");
    }
    const fractionDivisor =
      header.timestampResolution === "microseconds" ? 1_000_000 : 1_000_000_000;
    const timestamp = timestampSeconds + timestampFraction / fractionDivisor;
    firstTimestamp ??= timestamp;
    lastTimestamp = timestamp;
    packetCount += 1;
    capturedBytes += includedLength;
    originalBytes += originalLength;
    const packet = buffer.subarray(offset + 16, offset + 16 + includedLength);
    offset += 16 + includedLength;
    protocols.ethernet += 1;
    if (packet.byteLength < 14) continue;

    let etherType = packet.readUInt16BE(12);
    let networkOffset = 14;
    for (let vlan = 0; vlan < 2 && (etherType === 0x8100 || etherType === 0x88a8); vlan += 1) {
      if (packet.byteLength < networkOffset + 4) break;
      etherType = packet.readUInt16BE(networkOffset + 2);
      networkOffset += 4;
    }
    if (etherType === 0x86dd) {
      protocols.ipv6 += 1;
      continue;
    }
    if (etherType === 0x0806) {
      protocols.arp += 1;
      continue;
    }
    if (etherType !== 0x0800) {
      protocols.other += 1;
      continue;
    }
    protocols.ipv4 += 1;
    if (packet.byteLength < networkOffset + 20) continue;
    const versionIhl = packet[networkOffset]!;
    if (versionIhl >> 4 !== 4) continue;
    const ipHeaderLength = (versionIhl & 0x0f) * 4;
    if (ipHeaderLength < 20 || packet.byteLength < networkOffset + ipHeaderLength) continue;
    const totalLength = packet.readUInt16BE(networkOffset + 2);
    if (totalLength < ipHeaderLength) continue;
    const ipEnd = Math.min(packet.byteLength, networkOffset + totalLength);
    const source = ipv4Address(packet, networkOffset + 12);
    const destination = ipv4Address(packet, networkOffset + 16);
    increment(talkers, source);
    increment(talkers, destination);
    increment(conversations, `${source}>${destination}`);
    const protocol = packet[networkOffset + 9]!;
    const transportOffset = networkOffset + ipHeaderLength;
    const fragmentOffset = packet.readUInt16BE(networkOffset + 6) & 0x1fff;

    if (protocol === 1) {
      protocols.icmp += 1;
      continue;
    }
    if (protocol === 6) {
      protocols.tcp += 1;
      if (fragmentOffset !== 0) continue;
      if (ipEnd - transportOffset < 20) continue;
      const sourcePort = packet.readUInt16BE(transportOffset);
      const destinationPort = packet.readUInt16BE(transportOffset + 2);
      const sequence = packet.readUInt32BE(transportOffset + 4);
      const tcpHeaderLength = (packet[transportOffset + 12]! >> 4) * 4;
      if (tcpHeaderLength < 20 || transportOffset + tcpHeaderLength > ipEnd) continue;
      const flags = packet[transportOffset + 13]!;
      const window = packet.readUInt16BE(transportOffset + 14);
      if ((flags & 0x04) !== 0) tcpRst += 1;
      if (window === 0) tcpZeroWindow += 1;
      const payloadLength = Math.max(0, ipEnd - transportOffset - tcpHeaderLength);
      const consumed =
        payloadLength + ((flags & 0x02) !== 0 ? 1 : 0) + ((flags & 0x01) !== 0 ? 1 : 0);
      if (consumed > 0) {
        const flow = `${source}:${sourcePort}>${destination}:${destinationPort}`;
        const range = `${flow}:${sequence}:${consumed}`;
        if (seenTcpRanges.has(range)) {
          retransmissions.push({ packet: packetCount, flow, sequence, consumed });
        } else {
          seenTcpRanges.add(range);
        }
      }
      if (
        (sourcePort === 53 || destinationPort === 53) &&
        ipEnd - (transportOffset + tcpHeaderLength) >= 14
      ) {
        const dnsOffset = transportOffset + tcpHeaderLength;
        const dnsLength = packet.readUInt16BE(dnsOffset);
        if (dnsLength >= 12 && dnsLength <= ipEnd - dnsOffset - 2) {
          const flagsValue = packet.readUInt16BE(dnsOffset + 4);
          if ((flagsValue & 0x8000) === 0) dnsQueries += 1;
          else dnsResponses += 1;
        }
      }
      continue;
    }
    if (protocol === 17) {
      protocols.udp += 1;
      if (fragmentOffset !== 0) continue;
      if (ipEnd - transportOffset < 8) continue;
      const sourcePort = packet.readUInt16BE(transportOffset);
      const destinationPort = packet.readUInt16BE(transportOffset + 2);
      const dnsOffset = transportOffset + 8;
      if ((sourcePort === 53 || destinationPort === 53) && ipEnd - dnsOffset >= 4) {
        const flagsValue = packet.readUInt16BE(dnsOffset + 2);
        if ((flagsValue & 0x8000) === 0) dnsQueries += 1;
        else dnsResponses += 1;
      }
      continue;
    }
    protocols.other += 1;
  }

  const retransmissionRate = percentage(retransmissions.length, protocols.tcp);
  return {
    schema_version: "1",
    analyzer_version: ANALYZER_VERSION,
    artifact_id: artifactId,
    facts: [
      {
        fact_id: "fact.capture.metadata",
        kind: "capture_metadata",
        value: {
          packets: packetCount,
          captured_bytes: capturedBytes,
          original_bytes: originalBytes,
          first_timestamp: firstTimestamp ?? null,
          last_timestamp: lastTimestamp ?? null,
          byte_order: header.byteOrder,
          timestamp_resolution: header.timestampResolution,
          snaplen: header.snaplen,
          link_type: header.linkType,
        },
      },
      { fact_id: "fact.protocol.counts", kind: "protocol_counts", value: protocols },
      { fact_id: "fact.ipv4.top_talkers", kind: "ipv4_top_talkers", value: ranked(talkers) },
      {
        fact_id: "fact.ipv4.conversations",
        kind: "ipv4_conversations",
        value: ranked(conversations),
      },
      {
        fact_id: "fact.tcp.flags",
        kind: "tcp_flags",
        value: { rst_packets: tcpRst, zero_window_packets: tcpZeroWindow },
      },
      {
        fact_id: "fact.tcp.retransmissions",
        kind: "tcp_retransmissions",
        value: {
          retransmission_packets: retransmissions.length,
          tcp_packets: protocols.tcp,
          retransmission_percent: retransmissionRate,
          evidence: retransmissions.slice(0, 100),
        },
      },
      {
        fact_id: "fact.dns.qr_counts",
        kind: "dns_qr_counts",
        value: { queries: dnsQueries, responses: dnsResponses },
      },
    ],
    metrics: {
      tcp_retransmission_percent: retransmissionRate,
      tcp_retransmissions: retransmissions.length,
      tcp_packets: protocols.tcp,
    },
  };
}

export async function analyzeClassicPcapFile(
  filePath: string,
  artifactId: string,
  limits: PcapAnalysisLimits,
): Promise<PcapAnalysis> {
  const info = await stat(filePath);
  if (!info.isFile()) throw invalid("PCAP artifact is not a regular file.");
  if (info.size > limits.maxBytes)
    throw limited(`PCAP exceeds the ${limits.maxBytes}-byte analysis limit.`);
  return analyzeClassicPcapBytes(await readFile(filePath), artifactId, limits);
}
