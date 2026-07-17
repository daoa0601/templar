import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { TemplarConfig } from "../src/config.js";

export async function temporaryDirectory(prefix = "templar-test-"): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function testConfig(overrides: Partial<TemplarConfig> = {}): Promise<TemplarConfig> {
  const templarHome = overrides.templarHome ?? (await temporaryDirectory());
  return {
    host: "127.0.0.1",
    port: 0,
    templarHome,
    artifactRoot: path.join(templarHome, "artifacts", "pcap"),
    harnessHome: path.join(templarHome, "harness"),
    maxActiveRuns: 2,
    maxJsonBytes: 4096,
    maxPcapBytes: 1024 * 1024,
    maxPcapPackets: 100,
    ...overrides,
  };
}

function ethernetIpv4(
  protocol: number,
  payload: Buffer,
  source: ReadonlyArray<number>,
  destination: ReadonlyArray<number>,
  fragmentOffset = 0,
): Buffer {
  const ethernet = Buffer.alloc(14);
  ethernet.writeUInt16BE(0x0800, 12);
  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + payload.length, 2);
  ip[8] = 64;
  ip[9] = protocol;
  ip.writeUInt16BE(fragmentOffset & 0x1fff, 6);
  Buffer.from(source).copy(ip, 12);
  Buffer.from(destination).copy(ip, 16);
  return Buffer.concat([ethernet, ip, payload]);
}

export function tcpPacket(options: {
  readonly sequence: number;
  readonly flags: number;
  readonly window?: number;
  readonly payload?: string;
  readonly sourcePort?: number;
  readonly destinationPort?: number;
}): Buffer {
  const payload = Buffer.from(options.payload ?? "");
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(options.sourcePort ?? 1234, 0);
  tcp.writeUInt16BE(options.destinationPort ?? 80, 2);
  tcp.writeUInt32BE(options.sequence, 4);
  tcp[12] = 0x50;
  tcp[13] = options.flags;
  tcp.writeUInt16BE(options.window ?? 4096, 14);
  return ethernetIpv4(6, Buffer.concat([tcp, payload]), [10, 0, 0, 1], [10, 0, 0, 2]);
}

export function dnsPacket(response: boolean): Buffer {
  const dns = Buffer.alloc(12);
  dns.writeUInt16BE(0x1234, 0);
  dns.writeUInt16BE(response ? 0x8180 : 0x0100, 2);
  const udp = Buffer.alloc(8);
  udp.writeUInt16BE(response ? 53 : 53000, 0);
  udp.writeUInt16BE(response ? 53000 : 53, 2);
  udp.writeUInt16BE(8 + dns.length, 4);
  return ethernetIpv4(
    17,
    Buffer.concat([udp, dns]),
    [192, 0, 2, response ? 53 : 10],
    [192, 0, 2, response ? 10 : 53],
  );
}

export function tcpDnsPacket(response: boolean): Buffer {
  const dns = Buffer.alloc(12);
  dns.writeUInt16BE(0x1234, 0);
  dns.writeUInt16BE(response ? 0x8180 : 0x0100, 2);
  const framedDns = Buffer.alloc(2 + dns.length);
  framedDns.writeUInt16BE(dns.length, 0);
  dns.copy(framedDns, 2);
  const tcp = Buffer.alloc(20);
  tcp.writeUInt16BE(response ? 53 : 53000, 0);
  tcp.writeUInt16BE(response ? 53000 : 53, 2);
  tcp.writeUInt32BE(100, 4);
  tcp[12] = 0x50;
  tcp[13] = 0x18;
  tcp.writeUInt16BE(4096, 14);
  return ethernetIpv4(
    6,
    Buffer.concat([tcp, framedDns]),
    [192, 0, 2, response ? 53 : 10],
    [192, 0, 2, response ? 10 : 53],
  );
}

export function nonInitialDnsLikeFragment(): Buffer {
  const payload = Buffer.alloc(20);
  payload.writeUInt16BE(53000, 0);
  payload.writeUInt16BE(53, 2);
  payload.writeUInt16BE(20, 4);
  payload.writeUInt16BE(0x0100, 10);
  return ethernetIpv4(17, payload, [192, 0, 2, 10], [192, 0, 2, 53], 1);
}

export function classicPcap(packets: ReadonlyArray<Buffer>): Buffer {
  const header = Buffer.alloc(24);
  Buffer.from([0xd4, 0xc3, 0xb2, 0xa1]).copy(header);
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeUInt32LE(65_535, 16);
  header.writeUInt32LE(1, 20);
  const records = packets.map((packet, index) => {
    const record = Buffer.alloc(16);
    record.writeUInt32LE(1_700_000_000 + index, 0);
    record.writeUInt32LE(0, 4);
    record.writeUInt32LE(packet.length, 8);
    record.writeUInt32LE(packet.length, 12);
    return Buffer.concat([record, packet]);
  });
  return Buffer.concat([header, ...records]);
}
