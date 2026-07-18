import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { xorPeRvaRange } from "../src/pe-transform.js";

function fixture(): Buffer {
  const bytes = Buffer.alloc(0x600);
  bytes.write("MZ");
  bytes.writeUInt32LE(0x80, 0x3c);
  bytes.write("PE\0\0", 0x80, "latin1");
  bytes.writeUInt16LE(0x14c, 0x84);
  bytes.writeUInt16LE(1, 0x86);
  bytes.writeUInt16LE(0xe0, 0x94);
  bytes.writeUInt16LE(0x10b, 0x98);
  bytes.writeUInt32LE(0x1000, 0xa8);
  const section = 0x178;
  bytes.write(".text", section, "ascii");
  bytes.writeUInt32LE(0x100, section + 8);
  bytes.writeUInt32LE(0x1000, section + 12);
  bytes.writeUInt32LE(0x100, section + 16);
  bytes.writeUInt32LE(0x400, section + 20);
  for (let index = 0; index < 0x100; index += 1) bytes[0x400 + index] = index;
  return bytes;
}

describe("bounded PE analysis transformations", () => {
  it("maps an RVA into a copied file-backed section and records custody", () => {
    const input = fixture();
    const inputDigest = createHash("sha256").update(input).digest("hex");
    const transformed = xorPeRvaRange(input, {
      startRva: 0x1010,
      length: 4,
      xorByte: 0xff,
      expectedInputSha256: inputDigest,
    });
    expect(transformed).toMatchObject({
      section: ".text",
      file_offset: 0x410,
      start_rva: 0x1010,
      length: 4,
      xor_byte: 0xff,
      input_sha256: inputDigest,
      entrypoint_rva: 0x1000,
    });
    expect(transformed.bytes.subarray(0x410, 0x414)).toEqual(Buffer.from([0xef, 0xee, 0xed, 0xec]));
    expect(input.subarray(0x410, 0x414)).toEqual(Buffer.from([0x10, 0x11, 0x12, 0x13]));
  });

  it("rejects digest mismatch and ranges outside raw section bytes", () => {
    expect(() =>
      xorPeRvaRange(fixture(), {
        startRva: 0x1000,
        length: 1,
        xorByte: 1,
        expectedInputSha256: "0".repeat(64),
      }),
    ).toThrow(/expected transformation input digest/u);
    expect(() => xorPeRvaRange(fixture(), { startRva: 0x10ff, length: 2, xorByte: 1 })).toThrow(
      /not fully file-backed/u,
    );
  });
});
