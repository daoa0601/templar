import { TemplarError } from "./errors.js";

export interface ClassicPcapHeader {
  readonly byteOrder: "little" | "big";
  readonly timestampResolution: "microseconds" | "nanoseconds";
  readonly versionMajor: number;
  readonly versionMinor: number;
  readonly snaplen: number;
  readonly linkType: 1;
}

function pcapInvalid(message: string): TemplarError {
  return new TemplarError({ code: "PCAP_INVALID", message, status: 400 });
}

export function inspectClassicPcapHeader(bytes: Uint8Array): ClassicPcapHeader {
  if (bytes.byteLength < 4) throw pcapInvalid("PCAP global header is truncated.");
  const prefix = Buffer.from(bytes.buffer, bytes.byteOffset, Math.min(bytes.byteLength, 24));
  if (prefix.subarray(0, 4).equals(Buffer.from([0x0a, 0x0d, 0x0d, 0x0a]))) {
    throw pcapInvalid("pcapng is not supported; upload a classic PCAP file.");
  }
  if (bytes.byteLength < 24) throw pcapInvalid("PCAP global header is truncated.");

  const magic = prefix.subarray(0, 4).toString("hex");
  let byteOrder: ClassicPcapHeader["byteOrder"];
  let timestampResolution: ClassicPcapHeader["timestampResolution"];
  if (magic === "d4c3b2a1") {
    byteOrder = "little";
    timestampResolution = "microseconds";
  } else if (magic === "a1b2c3d4") {
    byteOrder = "big";
    timestampResolution = "microseconds";
  } else if (magic === "4d3cb2a1") {
    byteOrder = "little";
    timestampResolution = "nanoseconds";
  } else if (magic === "a1b23c4d") {
    byteOrder = "big";
    timestampResolution = "nanoseconds";
  } else {
    throw pcapInvalid("Unsupported classic PCAP magic value.");
  }

  const read16 =
    byteOrder === "little" ? prefix.readUInt16LE.bind(prefix) : prefix.readUInt16BE.bind(prefix);
  const read32 =
    byteOrder === "little" ? prefix.readUInt32LE.bind(prefix) : prefix.readUInt32BE.bind(prefix);
  const versionMajor = read16(4);
  const versionMinor = read16(6);
  const snaplen = read32(16);
  const linkType = read32(20);
  if (versionMajor !== 2 || versionMinor !== 4) {
    throw pcapInvalid(`Unsupported PCAP version ${versionMajor}.${versionMinor}.`);
  }
  if (snaplen === 0) throw pcapInvalid("PCAP snaplen must be positive.");
  if (linkType !== 1) {
    throw pcapInvalid(`Unsupported PCAP link type ${linkType}; Ethernet (1) is required.`);
  }
  return {
    byteOrder,
    timestampResolution,
    versionMajor,
    versionMinor,
    snaplen,
    linkType: 1,
  };
}

export function readPcapUInt32(
  buffer: Buffer,
  offset: number,
  byteOrder: ClassicPcapHeader["byteOrder"],
): number {
  return byteOrder === "little" ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}
