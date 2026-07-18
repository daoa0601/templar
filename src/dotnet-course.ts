import { createDecipheriv } from "node:crypto";

import { runBoundedProcess } from "@agentic-orch/node-guardrails";

import { invalidInput } from "./errors.js";

export interface ConfuserXorShiftRecipe {
  readonly seed: number;
  readonly firstRightShift: number;
  readonly leftShift: number;
  readonly secondRightShift: number;
}

export interface ConfuserLzmaEnvelope {
  readonly properties: number;
  readonly lc: number;
  readonly lp: number;
  readonly pb: number;
  readonly dictionarySize: number;
  readonly outputSize: number;
  readonly compressed: Buffer;
}

function uint32(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw invalidInput(`${label} must be an unsigned 32-bit integer.`);
  }
  return value >>> 0;
}

function shift(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 31) {
    throw invalidInput(`${label} must be between 1 and 31.`);
  }
  return value;
}

function boundedBytes(input: Uint8Array, label: string, maximum: number, blockSize = 1): Buffer {
  if (input.byteLength === 0 || input.byteLength > maximum || input.byteLength % blockSize !== 0) {
    throw invalidInput(`${label} has an invalid bounded byte length.`);
  }
  return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
}

/**
 * Reproduce Confuser's common 16-word rolling XOR layer. Ciphertext words replace the key words,
 * so decoding is deliberately performed from an immutable input into a separate output buffer.
 */
export function decodeConfuserRollingXor(
  input: Uint8Array,
  recipe: ConfuserXorShiftRecipe,
  maximumBytes = 128 * 1024 * 1024,
): Buffer {
  const source = boundedBytes(input, "Confuser rolling-XOR input", maximumBytes, 4);
  let state = uint32(recipe.seed, "seed");
  const first = shift(recipe.firstRightShift, "firstRightShift");
  const left = shift(recipe.leftShift, "leftShift");
  const second = shift(recipe.secondRightShift, "secondRightShift");
  const key = new Uint32Array(16);
  for (let index = 0; index < key.length; index += 1) {
    state ^= state >>> first;
    state ^= state << left;
    state ^= state >>> second;
    state >>>= 0;
    key[index] = state;
  }

  const output = Buffer.allocUnsafe(source.length);
  for (let offset = 0, word = 0; offset < source.length; offset += 4, word += 1) {
    const encrypted = source.readUInt32LE(offset);
    const keyIndex = word & 15;
    output.writeUInt32LE((encrypted ^ key[keyIndex]!) >>> 0, offset);
    key[keyIndex] = encrypted;
  }
  return output;
}

/** Parse the compact LZMA1 envelope used by the managed packer without decompressing it. */
export function parseConfuserLzmaEnvelope(
  input: Uint8Array,
  maximumOutputBytes = 128 * 1024 * 1024,
): ConfuserLzmaEnvelope {
  const source = boundedBytes(input, "Confuser LZMA envelope", 128 * 1024 * 1024);
  if (source.length < 10) throw invalidInput("The Confuser LZMA envelope is truncated.");
  if (!Number.isSafeInteger(maximumOutputBytes) || maximumOutputBytes <= 0) {
    throw invalidInput("The LZMA output limit is invalid.");
  }
  const properties = source[0]!;
  if (properties >= 9 * 5 * 5) throw invalidInput("The LZMA property byte is invalid.");
  const lc = properties % 9;
  const remainder = Math.floor(properties / 9);
  const lp = remainder % 5;
  const pb = Math.floor(remainder / 5);
  const dictionarySize = source.readUInt32LE(1);
  const outputSize = source.readUInt32LE(5);
  if (
    dictionarySize === 0 ||
    outputSize === 0 ||
    outputSize > maximumOutputBytes ||
    source.length - 9 > maximumOutputBytes
  ) {
    throw invalidInput("The Confuser LZMA envelope exceeds its configured limits.");
  }
  return {
    properties,
    lc,
    lp,
    pb,
    dictionarySize,
    outputSize,
    compressed: Buffer.from(source.subarray(9)),
  };
}

/** Decompress one parsed managed-packer envelope through a bounded, direct xz process. */
export async function decompressConfuserLzma(options: {
  readonly envelope: Uint8Array;
  readonly executable: string;
  readonly cwd: string;
  readonly maximumOutputBytes?: number;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}): Promise<Buffer> {
  const parsed = parseConfuserLzmaEnvelope(
    options.envelope,
    options.maximumOutputBytes ?? 128 * 1024 * 1024,
  );
  // Confuser stores a four-byte decoded size after the standard five LZMA properties. xz's raw
  // decoder expects an end marker, which these streams omit. Reframe it as an LZMA-alone stream
  // with the declared eight-byte size so the decoder stops at the exact bounded output length.
  const lzmaAlone = Buffer.allocUnsafe(13 + parsed.compressed.length);
  Buffer.from(options.envelope.buffer, options.envelope.byteOffset, 5).copy(lzmaAlone, 0);
  lzmaAlone.writeBigUInt64LE(BigInt(parsed.outputSize), 5);
  parsed.compressed.copy(lzmaAlone, 13);
  const result = await runBoundedProcess({
    executable: options.executable,
    args: ["--format=lzma", "--decompress", "--stdout", "--single-stream"],
    cwd: options.cwd,
    stdin: lzmaAlone,
    timeoutMs: options.timeoutMs ?? 30_000,
    maxOutputBytes: parsed.outputSize + 1,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  if (result.exitCode !== 0 || result.stdout.length !== parsed.outputSize) {
    throw invalidInput("The Confuser LZMA payload did not decode to its declared size.");
  }
  return result.stdout;
}

/** Reproduce a managed DES-ECB resource layer without loading or executing the resulting assembly. */
export function decryptDesEcbResource(
  encryptedInput: Uint8Array,
  secretPrefix: string,
  fixedSuffix: string,
): Buffer {
  const encrypted = boundedBytes(encryptedInput, "DES resource ciphertext", 128 * 1024 * 1024, 8);
  if (!/^[\x20-\x7e]{4}$/u.test(secretPrefix) || !/^[\x20-\x7e]{4}$/u.test(fixedSuffix)) {
    throw invalidInput("The DES resource key components must be four printable ASCII bytes.");
  }
  const key8 = Buffer.from(`${secretPrefix}${fixedSuffix}`, "ascii");
  const key24 = Buffer.concat([key8, key8, key8]);
  try {
    const decipher = createDecipheriv("des-ede3", key24, null);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (cause) {
    throw invalidInput("The DES resource layer could not be decrypted.", cause);
  }
}

export interface PrefixedAesNote {
  readonly bytes: Buffer;
  readonly clearPrefix: Buffer;
  readonly key: Buffer;
}

/** Decrypt the course-style note whose first two clear bytes also prefix an AES-128-ECB key. */
export function decryptPrefixedAesNote(
  input: Uint8Array,
  fixedKeySuffix: Uint8Array,
): PrefixedAesNote {
  const source = boundedBytes(input, "prefixed AES note", 16 * 1024 * 1024);
  const suffix = boundedBytes(fixedKeySuffix, "AES key suffix", 14, 14);
  if (suffix.length !== 14 || source.length <= 2 || (source.length - 2) % 16 !== 0) {
    throw invalidInput("The prefixed AES note has an invalid layout.");
  }
  const prefix = Buffer.from(source.subarray(0, 2));
  const key = Buffer.concat([prefix, suffix]);
  try {
    const decipher = createDecipheriv("aes-128-ecb", key, null);
    const plaintext = Buffer.concat([decipher.update(source.subarray(2)), decipher.final()]);
    return { bytes: Buffer.concat([prefix, plaintext]), clearPrefix: prefix, key };
  } catch (cause) {
    throw invalidInput("The prefixed AES note could not be decrypted.", cause);
  }
}

/** Reproduce the modified Adler-32 validation routine recovered from the native sample. */
export function modifiedCourseAdler32(
  studentIdInput: string | Uint8Array,
  options: { readonly initialA?: number; readonly initialB?: number } = {},
): number {
  const bytes =
    typeof studentIdInput === "string" ? Buffer.from(studentIdInput, "utf8") : studentIdInput;
  if (bytes.byteLength === 0 || bytes.byteLength > 1024) {
    throw invalidInput("The checksum input has an invalid length.");
  }
  let a = uint32(options.initialA ?? 0x18b3_5470, "initialA");
  let b = uint32(options.initialB ?? 0, "initialB");
  const modulus = 65_521;
  for (const byte of bytes) {
    a = (a + byte) % modulus;
    b = (b + a) % modulus;
  }
  return (((b & 0xffff) << 16) | (a & 0xffff)) >>> 0;
}

export function checksumHex(checksum: number): string {
  return uint32(checksum, "checksum").toString(16).padStart(8, "0").toUpperCase();
}
