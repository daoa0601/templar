import { deflateRawSync } from "node:zlib";

import { describe, expect, it } from "vitest";

import {
  DOTNET_BUNDLE_SIGNATURE,
  extractDotnetBundleEntry,
  parseDotnetBundle,
} from "../src/dotnet-bundle.js";

function sevenBit(value: number): Buffer {
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

function string(value: string): Buffer {
  const bytes = Buffer.from(value);
  return Buffer.concat([sevenBit(bytes.length), bytes]);
}

function int64(value: number): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64LE(BigInt(value));
  return bytes;
}

function uint32(value: number): Buffer {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
}

function fixture(options: {
  readonly major: 1 | 6;
  readonly path?: string;
  readonly payload?: Buffer;
  readonly declaredSize?: number;
}): Buffer {
  const payload = options.payload ?? Buffer.from("managed payload");
  const stored = options.major >= 6 ? deflateRawSync(payload) : payload;
  const prefix = Buffer.alloc(96);
  const markerOffset = 24;
  DOTNET_BUNDLE_SIGNATURE.copy(prefix, markerOffset);
  const payloadOffset = prefix.length;
  const headerOffset = payloadOffset + stored.length;
  prefix.writeBigInt64LE(BigInt(headerOffset), markerOffset - 8);
  const header = Buffer.concat([
    uint32(options.major),
    uint32(0),
    uint32(1),
    string("fixture-id"),
    ...(options.major >= 2 ? [Buffer.alloc(40)] : []),
    int64(payloadOffset),
    int64(options.declaredSize ?? payload.length),
    ...(options.major >= 6 ? [int64(stored.length)] : []),
    Buffer.from([1]),
    string(options.path ?? "fixture.dll"),
  ]);
  return Buffer.concat([prefix, stored, header]);
}

describe("passive .NET single-file bundle parsing", () => {
  it("parses and extracts a v1 uncompressed assembly", () => {
    const bytes = fixture({ major: 1 });
    const bundle = parseDotnetBundle(bytes);
    expect(bundle).toMatchObject({
      majorVersion: 1,
      minorVersion: 0,
      bundleId: "fixture-id",
      markerOffset: 24,
    });
    expect(bundle.entries).toEqual([
      expect.objectContaining({ path: "fixture.dll", type: 1, size: 15, compressedSize: 0 }),
    ]);
    expect(extractDotnetBundleEntry(bytes, bundle, bundle.entries[0]!)).toEqual(
      Buffer.from("managed payload"),
    );
  });

  it("inflates a v6 raw-deflate entry and verifies its decoded size", () => {
    const bytes = fixture({ major: 6, payload: Buffer.from("compressed managed payload") });
    const bundle = parseDotnetBundle(bytes);
    expect(bundle.majorVersion).toBe(6);
    expect(bundle.entries[0]!.compressedSize).toBeGreaterThan(0);
    expect(extractDotnetBundleEntry(bytes, bundle, bundle.entries[0]!)).toEqual(
      Buffer.from("compressed managed payload"),
    );

    const bad = fixture({ major: 6, declaredSize: 100 });
    const parsed = parseDotnetBundle(bad);
    expect(() => extractDotnetBundleEntry(bad, parsed, parsed.entries[0]!)).toThrow(
      /invalid decoded size/u,
    );
  });

  it("rejects missing markers, traversal paths, and out-of-range entries", () => {
    expect(() => parseDotnetBundle(Buffer.alloc(128))).toThrow(/marker is missing/u);
    expect(() => parseDotnetBundle(fixture({ major: 1, path: "../escape.dll" }))).toThrow(
      /unsafe path segment/u,
    );
    expect(() => parseDotnetBundle(fixture({ major: 1, declaredSize: 10_000 }))).toThrow(
      /invalid byte range/u,
    );
  });

  it("enforces caller-supplied bundle and entry limits", () => {
    const bytes = fixture({ major: 1 });
    expect(() => parseDotnetBundle(bytes, { maxBundleBytes: bytes.length - 1 })).toThrow(
      /bundle is empty or exceeds/u,
    );
    expect(() => parseDotnetBundle(bytes, { maxEntryBytes: 4 })).toThrow(
      /exceeds the configured byte limit/u,
    );
  });
});
