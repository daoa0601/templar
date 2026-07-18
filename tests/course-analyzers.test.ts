import { createCipheriv } from "node:crypto";

import { describe, expect, it } from "vitest";

import { analyzeDarkwoodSample, DOTNET_BUNDLE_SIGNATURE } from "../src/index.js";

function sevenBit(value: number): Buffer {
  const output: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining > 0) byte |= 0x80;
    output.push(byte);
  } while (remaining > 0);
  return Buffer.from(output);
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

function darkwoodFixture(extraAssemblyString = ""): Buffer {
  const key = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  const iv = "Wikipedia, the f";
  const cipher = createCipheriv("aes-256-cbc", Buffer.from(key), Buffer.from(iv));
  const ciphertext = Buffer.concat([cipher.update("fixture-secret"), cipher.final()])
    .toString("hex")
    .match(/../gu)!
    .join("-")
    .toUpperCase();
  const assembly = Buffer.concat([
    Buffer.from("MZ"),
    Buffer.alloc(126),
    Buffer.from(`${ciphertext}\0${key}\0${IV_MARKER_FOR_FIXTURE}\0${extraAssemblyString}\0`),
  ]);
  const prefix = Buffer.alloc(96);
  const markerOffset = 24;
  const payloadOffset = prefix.length;
  const headerOffset = payloadOffset + assembly.length;
  prefix.writeBigInt64LE(BigInt(headerOffset), markerOffset - 8);
  DOTNET_BUNDLE_SIGNATURE.copy(prefix, markerOffset);
  const header = Buffer.concat([
    uint32(1),
    uint32(0),
    uint32(1),
    string("fixture-bundle"),
    int64(payloadOffset),
    int64(assembly.length),
    Buffer.from([1]),
    string("darkwood_FIXTURE.dll"),
  ]);
  return Buffer.concat([prefix, assembly, header]);
}

const IV_MARKER_FOR_FIXTURE = "Wikipedia, the free encyclopedia";

describe("passive course specimen analyzers", () => {
  it("extracts and decrypts a Darkwood managed bundle without executing it", () => {
    expect(analyzeDarkwoodSample(darkwoodFixture(), "darkwood_FIXTURE.exe")).toMatchObject({
      sample_name: "darkwood_FIXTURE.exe",
      bundle_version: "1.0",
      bundle_id: "fixture-bundle",
      assembly_path: "darkwood_FIXTURE.dll",
      algorithm: "AES-256-CBC-PKCS7",
      key: "0123456789ABCDEFGHIJKLMNOPQRSTUV",
      iv: "Wikipedia, the f",
      decrypted_secret: "fixture-secret",
    });
  });

  it("rejects renamed samples and ambiguous keys", () => {
    const bytes = darkwoodFixture();
    expect(() => analyzeDarkwoodSample(bytes, "../darkwood_FIXTURE.exe")).toThrow(
      /sample name is invalid/u,
    );
    const ambiguous = darkwoodFixture("ZYXWVUTSRQPONMLKJIHGFEDCBA987654");
    expect(() => analyzeDarkwoodSample(ambiguous, "darkwood_FIXTURE.exe")).toThrow(
      /marker is ambiguous|32-byte key/u,
    );
  });
});
