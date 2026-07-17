import { readFile, symlink, unlink } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { analyzeClassicPcapBytes } from "../src/pcap-analyzer.js";
import { PcapArtifactStore } from "../src/pcap-store.js";
import {
  classicPcap,
  dnsPacket,
  nonInitialDnsLikeFragment,
  tcpDnsPacket,
  tcpPacket,
  temporaryDirectory,
} from "./helpers.js";

const limits = { maxBytes: 1024 * 1024, maxPackets: 100 };

function fact<T = Record<string, number>>(
  analysis: ReturnType<typeof analyzeClassicPcapBytes>,
  id: string,
): T {
  return analysis.facts.find((item) => item.fact_id === id)?.value as T;
}

describe("bounded classic-PCAP analysis", () => {
  it("does not classify repeated pure ACKs as retransmissions", () => {
    const capture = classicPcap([
      tcpPacket({ sequence: 100, flags: 0x10 }),
      tcpPacket({ sequence: 100, flags: 0x10 }),
    ]);
    const analysis = analyzeClassicPcapBytes(capture, "pcap_sha256_test", limits);
    expect(analysis.metrics.tcp_retransmissions).toBe(0);
  });

  it("finds true payload retransmission, RST, and zero-window evidence", () => {
    const capture = classicPcap([
      tcpPacket({ sequence: 100, flags: 0x18, payload: "abc" }),
      tcpPacket({ sequence: 100, flags: 0x18, payload: "abc" }),
      tcpPacket({ sequence: 200, flags: 0x14, window: 0 }),
    ]);
    const analysis = analyzeClassicPcapBytes(capture, "pcap_sha256_test", limits);
    expect(analysis.metrics).toEqual({
      tcp_retransmission_percent: 33.333333,
      tcp_retransmissions: 1,
      tcp_packets: 3,
    });
    expect(fact(analysis, "fact.tcp.flags")).toEqual({ rst_packets: 1, zero_window_packets: 1 });
  });

  it("accounts for SYN and FIN sequence consumption when finding retransmissions", () => {
    const analysis = analyzeClassicPcapBytes(
      classicPcap([
        tcpPacket({ sequence: 100, flags: 0x02 }),
        tcpPacket({ sequence: 100, flags: 0x02 }),
        tcpPacket({ sequence: 200, flags: 0x11 }),
        tcpPacket({ sequence: 200, flags: 0x11 }),
      ]),
      "pcap_sha256_test",
      limits,
    );
    expect(analysis.metrics).toMatchObject({ tcp_retransmissions: 2, tcp_packets: 4 });
    const retransmissions = fact(analysis, "fact.tcp.retransmissions")
      .evidence as unknown as ReadonlyArray<{
      readonly sequence: number;
      readonly consumed: number;
    }>;
    expect(retransmissions).toEqual([
      expect.objectContaining({ sequence: 100, consumed: 1 }),
      expect.objectContaining({ sequence: 200, consumed: 1 }),
    ]);
  });

  it("uses the DNS QR flag for query/response classification", () => {
    const analysis = analyzeClassicPcapBytes(
      classicPcap([dnsPacket(false), dnsPacket(true)]),
      "pcap_sha256_test",
      limits,
    );
    expect(fact(analysis, "fact.dns.qr_counts")).toEqual({ queries: 1, responses: 1 });
  });

  it("uses the DNS-over-TCP length prefix before reading the QR flag", () => {
    const analysis = analyzeClassicPcapBytes(
      classicPcap([tcpDnsPacket(false), tcpDnsPacket(true)]),
      "pcap_sha256_test",
      limits,
    );
    expect(fact(analysis, "fact.dns.qr_counts")).toEqual({ queries: 1, responses: 1 });
  });

  it("does not parse transport headers from non-initial IPv4 fragments", () => {
    const analysis = analyzeClassicPcapBytes(
      classicPcap([nonInitialDnsLikeFragment()]),
      "pcap_sha256_test",
      limits,
    );
    expect(fact(analysis, "fact.dns.qr_counts")).toEqual({ queries: 0, responses: 0 });
  });

  it("profiles destination services, transport conversations, and source fan-out", () => {
    const analysis = analyzeClassicPcapBytes(
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
          flags: 0x04,
          sourcePort: 40_001,
          destinationPort: 5678,
          destination: [10, 0, 0, 3],
        }),
        tcpPacket({
          sequence: 3,
          flags: 0x02,
          sourcePort: 40_000,
          destinationPort: 25,
          destination: [10, 0, 0, 2],
        }),
      ]),
      "pcap_sha256_test",
      limits,
    );

    expect(
      fact<ReadonlyArray<Record<string, number | string>>>(
        analysis,
        "fact.transport.destination_ports",
      ),
    ).toEqual([
      { protocol: "tcp", port: 25, packets: 2 },
      { protocol: "tcp", port: 5678, packets: 1 },
    ]);
    expect(
      fact<ReadonlyArray<Record<string, number | string>>>(
        analysis,
        "fact.transport.conversations",
      )[0],
    ).toEqual({
      protocol: "tcp",
      source: "10.0.0.1",
      source_port: 40_000,
      destination: "10.0.0.2",
      destination_port: 25,
      packets: 2,
    });
    expect(
      fact<ReadonlyArray<Record<string, number | string>>>(
        analysis,
        "fact.transport.source_profiles",
      )[0],
    ).toEqual({
      source: "10.0.0.1",
      packets: 3,
      unique_destinations: 2,
      unique_destination_ports: 2,
      unique_endpoints: 2,
      tcp_syn_without_ack_packets: 2,
      tcp_rst_packets: 1,
    });
  });

  it("enforces byte and packet limits and rejects bad formats", () => {
    const capture = classicPcap([
      tcpPacket({ sequence: 1, flags: 0x02 }),
      tcpPacket({ sequence: 2, flags: 0x02 }),
    ]);
    expect(() =>
      analyzeClassicPcapBytes(capture, "id", { ...limits, maxBytes: capture.length - 1 }),
    ).toThrow(/byte analysis limit/u);
    expect(() => analyzeClassicPcapBytes(capture, "id", { ...limits, maxPackets: 1 })).toThrow(
      /packet analysis limit/u,
    );
    expect(() => analyzeClassicPcapBytes(Buffer.alloc(24), "id", limits)).toThrow(/magic/u);
    expect(() =>
      analyzeClassicPcapBytes(Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]), "id", limits),
    ).toThrow(/pcapng/u);
  });

  it("stages by digest and rejects symlink resolution", async () => {
    const root = await temporaryDirectory("templar-pcap-");
    const store = new PcapArtifactStore(root, limits.maxBytes);
    const capture = classicPcap([]);
    const stored = await store.stage(capture);
    const resolved = await store.resolve(stored.artifact_id);
    expect(await readFile(resolved)).toEqual(capture);
    await unlink(resolved);
    await symlink("/dev/null", resolved);
    await expect(store.resolve(stored.artifact_id)).rejects.toThrow(/regular file/u);
  });
});
