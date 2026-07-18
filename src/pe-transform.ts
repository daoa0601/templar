import { createHash } from "node:crypto";

import { invalidInput } from "./errors.js";

export const DYNAMIC_X86_SAMPLE_SHA256 =
  "e5fac9d86e01d9ad67bf3049435a447cd7b751a4d458d746ac21f752ce80af42";
export const DYNAMIC_X86_DECODED_SHA256 =
  "990f90be6e8d55e7000f5d8ab560307a435e028b70b57fffb3c44f6ce371d263";

export interface PeXorTransformation {
  readonly bytes: Buffer;
  readonly section: string;
  readonly file_offset: number;
  readonly start_rva: number;
  readonly length: number;
  readonly xor_byte: number;
  readonly input_sha256: string;
  readonly output_sha256: string;
  readonly entrypoint_rva: number;
}

interface PeSection {
  readonly name: string;
  readonly virtualAddress: number;
  readonly virtualSize: number;
  readonly rawOffset: number;
  readonly rawSize: number;
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function range(bytes: Buffer, offset: number, length: number, label: string): void {
  if (
    !Number.isSafeInteger(offset) ||
    !Number.isSafeInteger(length) ||
    offset < 0 ||
    length < 0 ||
    offset + length > bytes.length
  ) {
    throw invalidInput(`The PE ended while reading ${label}.`);
  }
}

function peLayout(bytes: Buffer): {
  readonly entrypointRva: number;
  readonly sections: PeSection[];
} {
  range(bytes, 0, 0x40, "DOS header");
  if (bytes.subarray(0, 2).toString("ascii") !== "MZ")
    throw invalidInput("PE DOS magic is invalid.");
  const peOffset = bytes.readUInt32LE(0x3c);
  range(bytes, peOffset, 24, "PE header");
  if (bytes.subarray(peOffset, peOffset + 4).toString("latin1") !== "PE\0\0") {
    throw invalidInput("PE signature is invalid.");
  }
  const sectionCount = bytes.readUInt16LE(peOffset + 6);
  const optionalSize = bytes.readUInt16LE(peOffset + 20);
  if (sectionCount === 0 || sectionCount > 96) throw invalidInput("PE section count is invalid.");
  const optionalOffset = peOffset + 24;
  range(bytes, optionalOffset, optionalSize, "PE optional header");
  const magic = bytes.readUInt16LE(optionalOffset);
  if (magic !== 0x10b && magic !== 0x20b)
    throw invalidInput("PE optional-header magic is invalid.");
  if (optionalSize < 20) throw invalidInput("PE optional header is too short.");
  const entrypointRva = bytes.readUInt32LE(optionalOffset + 16);
  const tableOffset = optionalOffset + optionalSize;
  range(bytes, tableOffset, sectionCount * 40, "PE section table");
  const sections: PeSection[] = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const offset = tableOffset + index * 40;
    const name = bytes
      .subarray(offset, offset + 8)
      .subarray(0, bytes.subarray(offset, offset + 8).indexOf(0) >>> 0)
      .toString("ascii");
    const virtualSize = bytes.readUInt32LE(offset + 8);
    const virtualAddress = bytes.readUInt32LE(offset + 12);
    const rawSize = bytes.readUInt32LE(offset + 16);
    const rawOffset = bytes.readUInt32LE(offset + 20);
    range(bytes, rawOffset, rawSize, `PE section ${name}`);
    sections.push({ name, virtualAddress, virtualSize, rawOffset, rawSize });
  }
  return { entrypointRva, sections };
}

/** Copy and XOR one fully file-backed PE RVA range; the input is never modified. */
export function xorPeRvaRange(
  input: Uint8Array,
  options: {
    readonly startRva: number;
    readonly length: number;
    readonly xorByte: number;
    readonly expectedInputSha256?: string;
  },
): PeXorTransformation {
  if (input.byteLength === 0 || input.byteLength > 256 * 1024 * 1024) {
    throw invalidInput("The PE is empty or exceeds the transformation byte limit.");
  }
  if (
    !Number.isSafeInteger(options.startRva) ||
    options.startRva < 0 ||
    !Number.isSafeInteger(options.length) ||
    options.length <= 0 ||
    !Number.isSafeInteger(options.xorByte) ||
    options.xorByte < 0 ||
    options.xorByte > 0xff
  ) {
    throw invalidInput("The PE XOR transformation parameters are invalid.");
  }
  const source = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const inputSha256 = digest(source);
  if (options.expectedInputSha256 !== undefined && inputSha256 !== options.expectedInputSha256) {
    throw invalidInput("The PE does not match the expected transformation input digest.");
  }
  const layout = peLayout(source);
  const section = layout.sections.find(
    (candidate) =>
      options.startRva >= candidate.virtualAddress &&
      options.startRva + options.length <= candidate.virtualAddress + candidate.rawSize,
  );
  if (section === undefined) throw invalidInput("The PE XOR range is not fully file-backed.");
  const fileOffset = section.rawOffset + options.startRva - section.virtualAddress;
  const output = Buffer.from(source);
  for (let index = 0; index < options.length; index += 1) {
    output[fileOffset + index] = output[fileOffset + index]! ^ options.xorByte;
  }
  return {
    bytes: output,
    section: section.name,
    file_offset: fileOffset,
    start_rva: options.startRva,
    length: options.length,
    xor_byte: options.xorByte,
    input_sha256: inputSha256,
    output_sha256: digest(output),
    entrypoint_rva: layout.entrypointRva,
  };
}

/** Reproduce the course apphost's non-debugged PEB-key path as a static byte transformation. */
export function decodeDynamicX86CourseSample(input: Uint8Array): PeXorTransformation {
  const transformed = xorPeRvaRange(input, {
    startRva: 0x1000,
    length: 0x7bc,
    xorByte: 1,
    expectedInputSha256: DYNAMIC_X86_SAMPLE_SHA256,
  });
  if (
    transformed.entrypoint_rva !== 0x10_000 ||
    transformed.section !== ".text" ||
    transformed.output_sha256 !== DYNAMIC_X86_DECODED_SHA256
  ) {
    throw invalidInput("The decoded dynamic-x86 sample violates the corpus recipe.");
  }
  return transformed;
}
