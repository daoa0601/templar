import { createCipheriv } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  checksumHex,
  decodeConfuserRollingXor,
  decryptDesEcbResource,
  decryptPrefixedAesNote,
  modifiedCourseAdler32,
  parseConfuserLzmaEnvelope,
} from "../src/dotnet-course.js";

function encodedRollingXor(
  plaintext: Buffer,
  recipe: {
    readonly seed: number;
    readonly firstRightShift: number;
    readonly leftShift: number;
    readonly secondRightShift: number;
  },
): Buffer {
  let state = recipe.seed >>> 0;
  const key = new Uint32Array(16);
  for (let index = 0; index < 16; index += 1) {
    state ^= state >>> recipe.firstRightShift;
    state ^= state << recipe.leftShift;
    state ^= state >>> recipe.secondRightShift;
    state >>>= 0;
    key[index] = state;
  }
  const output = Buffer.alloc(plaintext.length);
  for (let offset = 0, word = 0; offset < plaintext.length; offset += 4, word += 1) {
    const encrypted = (plaintext.readUInt32LE(offset) ^ key[word & 15]!) >>> 0;
    output.writeUInt32LE(encrypted, offset);
    key[word & 15] = encrypted;
  }
  return output;
}

describe("passive managed and native course transforms", () => {
  it("decodes the rolling ciphertext-key XOR chain", () => {
    const recipe = {
      seed: 509_719_257,
      firstRightShift: 13,
      leftShift: 25,
      secondRightShift: 27,
    } as const;
    const plaintext = Buffer.alloc(80);
    for (let index = 0; index < plaintext.length; index += 1) plaintext[index] = index;
    expect(decodeConfuserRollingXor(encodedRollingXor(plaintext, recipe), recipe)).toEqual(
      plaintext,
    );
  });

  it("strictly parses the compact LZMA1 property and size header", () => {
    const envelope = Buffer.alloc(12);
    envelope[0] = 0x5d;
    envelope.writeUInt32LE(8 * 1024 * 1024, 1);
    envelope.writeUInt32LE(46_592, 5);
    envelope.set([1, 2, 3], 9);
    expect(parseConfuserLzmaEnvelope(envelope)).toMatchObject({
      lc: 3,
      lp: 0,
      pb: 2,
      dictionarySize: 8 * 1024 * 1024,
      outputSize: 46_592,
      compressed: Buffer.from([1, 2, 3]),
    });
    envelope[0] = 0xff;
    expect(() => parseConfuserLzmaEnvelope(envelope)).toThrow(/property byte/u);
  });

  it("reproduces DES and prefixed AES resource decryption without loading assemblies", () => {
    const desKey = Buffer.from("ABCDWXYZ");
    const desCipher = createCipheriv("des-ede3", Buffer.concat([desKey, desKey, desKey]), null);
    const encryptedResource = Buffer.concat([
      desCipher.update(Buffer.from("managed payload fixture")),
      desCipher.final(),
    ]);
    expect(decryptDesEcbResource(encryptedResource, "ABCD", "WXYZ").toString()).toBe(
      "managed payload fixture",
    );

    const prefix = Buffer.from("Co");
    const suffix = Buffer.from(Array.from({ length: 14 }, (_, index) => index + 1));
    const aesCipher = createCipheriv("aes-128-ecb", Buffer.concat([prefix, suffix]), null);
    const ciphertext = Buffer.concat([
      aesCipher.update(Buffer.from("bounded note fixture")),
      aesCipher.final(),
    ]);
    expect(decryptPrefixedAesNote(Buffer.concat([prefix, ciphertext]), suffix)).toMatchObject({
      bytes: Buffer.from("Cobounded note fixture"),
      clearPrefix: prefix,
      key: Buffer.concat([prefix, suffix]),
    });
  });

  it("calculates and formats the modified Adler validation value", () => {
    expect(checksumHex(modifiedCourseAdler32("123456"))).toBe("AE4CC831");
    expect(() => modifiedCourseAdler32("")).toThrow(/invalid length/u);
  });
});
