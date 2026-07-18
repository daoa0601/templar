import { inflateRawSync } from "node:zlib";

import { invalidInput } from "./errors.js";

/** Marker embedded in .NET apphosts immediately after the little-endian bundle-header offset. */
export const DOTNET_BUNDLE_SIGNATURE = Buffer.from(
  "8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae",
  "hex",
);

const SUPPORTED_BUNDLE_MAJORS = new Set([1, 2, 6]);

export interface DotnetBundleLimits {
  readonly maxBundleBytes: number;
  readonly maxEntries: number;
  readonly maxEntryBytes: number;
  readonly maxPathBytes: number;
}

const DEFAULT_LIMITS: DotnetBundleLimits = {
  maxBundleBytes: 1024 * 1024 * 1024,
  maxEntries: 4096,
  maxEntryBytes: 256 * 1024 * 1024,
  maxPathBytes: 4096,
};

export interface DotnetBundleEntry {
  readonly path: string;
  readonly type: number;
  readonly offset: number;
  readonly size: number;
  readonly compressedSize: number;
}

export interface DotnetBundle {
  readonly majorVersion: number;
  readonly minorVersion: number;
  readonly bundleId: string;
  readonly markerOffset: number;
  readonly headerOffset: number;
  readonly headerEnd: number;
  readonly entries: ReadonlyArray<DotnetBundleEntry>;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw invalidInput(`${label} must be a positive safe integer.`);
  }
  return value;
}

function limitsWithDefaults(overrides: Partial<DotnetBundleLimits>): DotnetBundleLimits {
  return {
    maxBundleBytes: positiveInteger(
      overrides.maxBundleBytes ?? DEFAULT_LIMITS.maxBundleBytes,
      "maxBundleBytes",
    ),
    maxEntries: positiveInteger(overrides.maxEntries ?? DEFAULT_LIMITS.maxEntries, "maxEntries"),
    maxEntryBytes: positiveInteger(
      overrides.maxEntryBytes ?? DEFAULT_LIMITS.maxEntryBytes,
      "maxEntryBytes",
    ),
    maxPathBytes: positiveInteger(
      overrides.maxPathBytes ?? DEFAULT_LIMITS.maxPathBytes,
      "maxPathBytes",
    ),
  };
}

function safeNumber(value: bigint, label: string): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw invalidInput(`${label} is outside the supported safe-integer range.`);
  }
  return Number(value);
}

function safeBundlePath(value: string): string {
  if (
    value.length === 0 ||
    value.includes(String.fromCharCode(0)) ||
    value.startsWith("/") ||
    value.startsWith("\\") ||
    /^[a-z]:/iu.test(value)
  ) {
    throw invalidInput("A .NET bundle entry has an unsafe path.");
  }
  const segments = value.replaceAll("\\", "/").split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw invalidInput("A .NET bundle entry has an unsafe path segment.");
  }
  return value;
}

class BundleReader {
  readonly #bytes: Buffer;
  readonly #limit: number;
  #offset: number;

  constructor(bytes: Buffer, offset: number, limit: number) {
    this.#bytes = bytes;
    this.#offset = offset;
    this.#limit = limit;
  }

  get offset(): number {
    return this.#offset;
  }

  #take(length: number, label: string): number {
    if (!Number.isSafeInteger(length) || length < 0 || this.#offset + length > this.#limit) {
      throw invalidInput(`The .NET bundle ended while reading ${label}.`);
    }
    const start = this.#offset;
    this.#offset += length;
    return start;
  }

  uint8(label: string): number {
    return this.#bytes[this.#take(1, label)]!;
  }

  uint32(label: string): number {
    return this.#bytes.readUInt32LE(this.#take(4, label));
  }

  int32(label: string): number {
    return this.#bytes.readInt32LE(this.#take(4, label));
  }

  int64(label: string): number {
    return safeNumber(this.#bytes.readBigInt64LE(this.#take(8, label)), label);
  }

  skip(length: number, label: string): void {
    this.#take(length, label);
  }

  string(label: string, maximumBytes: number): string {
    let length = 0;
    let shift = 0;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.uint8(`${label} length`);
      length |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        if (length > maximumBytes) {
          throw invalidInput(`${label} exceeds the configured byte limit.`);
        }
        const start = this.#take(length, label);
        const value = this.#bytes.subarray(start, start + length).toString("utf8");
        if (!Buffer.from(value, "utf8").equals(this.#bytes.subarray(start, start + length))) {
          throw invalidInput(`${label} is not valid UTF-8.`);
        }
        return value;
      }
      shift += 7;
    }
    throw invalidInput(`${label} has an invalid 7-bit encoded length.`);
  }
}

function bundleMarkerOffsets(bytes: Buffer): ReadonlyArray<number> {
  const offsets: number[] = [];
  let from = 0;
  while (from <= bytes.length - DOTNET_BUNDLE_SIGNATURE.length) {
    const found = bytes.indexOf(DOTNET_BUNDLE_SIGNATURE, from);
    if (found === -1) break;
    if (found >= 8) {
      const headerOffset = bytes.readBigInt64LE(found - 8);
      if (headerOffset >= 0n && headerOffset <= BigInt(bytes.length - 12)) offsets.push(found);
    }
    from = found + 1;
  }
  return offsets;
}

/** Parse the official .NET single-file bundle table without executing the apphost or payload. */
export function parseDotnetBundle(
  input: Uint8Array,
  limitOverrides: Partial<DotnetBundleLimits> = {},
): DotnetBundle {
  const limits = limitsWithDefaults(limitOverrides);
  if (input.byteLength === 0 || input.byteLength > limits.maxBundleBytes) {
    throw invalidInput("The .NET bundle is empty or exceeds the configured byte limit.");
  }
  const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const markers = bundleMarkerOffsets(bytes);
  if (markers.length !== 1) {
    throw invalidInput(
      markers.length === 0
        ? "The .NET bundle marker is missing."
        : "The .NET bundle marker is ambiguous.",
    );
  }

  const markerOffset = markers[0]!;
  const headerOffset = safeNumber(bytes.readBigInt64LE(markerOffset - 8), "bundle header offset");
  const reader = new BundleReader(bytes, headerOffset, bytes.length);
  const majorVersion = reader.uint32("bundle major version");
  const minorVersion = reader.uint32("bundle minor version");
  if (!SUPPORTED_BUNDLE_MAJORS.has(majorVersion)) {
    throw invalidInput(`Unsupported .NET bundle major version ${majorVersion}.`);
  }
  const entryCount = reader.int32("bundle entry count");
  if (entryCount <= 0 || entryCount > limits.maxEntries) {
    throw invalidInput("The .NET bundle entry count is outside the configured limit.");
  }
  const bundleId = reader.string("bundle ID", limits.maxPathBytes);
  if (bundleId.length === 0 || bundleId.includes(String.fromCharCode(0))) {
    throw invalidInput("The .NET bundle ID is invalid.");
  }

  if (majorVersion >= 2) {
    reader.skip(40, "bundle dependency locations and flags");
  }

  const entries: DotnetBundleEntry[] = [];
  const paths = new Set<string>();
  for (let index = 0; index < entryCount; index += 1) {
    const offset = reader.int64(`entry ${index} offset`);
    const size = reader.int64(`entry ${index} size`);
    const compressedSize = majorVersion >= 6 ? reader.int64(`entry ${index} compressed size`) : 0;
    const type = reader.uint8(`entry ${index} type`);
    const entryPath = safeBundlePath(reader.string(`entry ${index} path`, limits.maxPathBytes));
    if (paths.has(entryPath)) throw invalidInput(`Duplicate .NET bundle entry path ${entryPath}.`);
    paths.add(entryPath);
    if (size > limits.maxEntryBytes) {
      throw invalidInput(`.NET bundle entry ${entryPath} exceeds the configured byte limit.`);
    }
    const storedSize = compressedSize === 0 ? size : compressedSize;
    if (storedSize > limits.maxEntryBytes || offset + storedSize > headerOffset) {
      throw invalidInput(`.NET bundle entry ${entryPath} has an invalid byte range.`);
    }
    entries.push({ path: entryPath, type, offset, size, compressedSize });
  }

  return {
    majorVersion,
    minorVersion,
    bundleId,
    markerOffset,
    headerOffset,
    headerEnd: reader.offset,
    entries,
  };
}

/** Return a copied, bounded entry payload, inflating v6 raw-deflate entries when required. */
export function extractDotnetBundleEntry(
  input: Uint8Array,
  bundle: DotnetBundle,
  entry: DotnetBundleEntry,
  limitOverrides: Partial<DotnetBundleLimits> = {},
): Buffer {
  const limits = limitsWithDefaults(limitOverrides);
  if (!bundle.entries.includes(entry)) {
    throw invalidInput("The .NET bundle entry does not belong to the supplied bundle table.");
  }
  if (entry.size > limits.maxEntryBytes) {
    throw invalidInput(`.NET bundle entry ${entry.path} exceeds the configured byte limit.`);
  }
  const bytes = Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  const storedSize = entry.compressedSize === 0 ? entry.size : entry.compressedSize;
  if (entry.offset + storedSize > bytes.length) {
    throw invalidInput(`.NET bundle entry ${entry.path} has an invalid byte range.`);
  }
  const stored = bytes.subarray(entry.offset, entry.offset + storedSize);
  const extracted =
    entry.compressedSize === 0
      ? Buffer.from(stored)
      : inflateRawSync(stored, { maxOutputLength: limits.maxEntryBytes });
  if (extracted.length !== entry.size) {
    throw invalidInput(`.NET bundle entry ${entry.path} has an invalid decoded size.`);
  }
  return extracted;
}
