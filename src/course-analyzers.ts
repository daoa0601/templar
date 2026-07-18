import { createDecipheriv, createHash } from "node:crypto";
import path from "node:path";

import {
  extractDotnetBundleEntry,
  parseDotnetBundle,
  type DotnetBundleEntry,
} from "./dotnet-bundle.js";
import { invalidInput } from "./errors.js";

const DARKWOOD_SAMPLE = /^darkwood_[a-z0-9]+\.exe$/iu;
const CIPHER_TEXT = /(?:[a-f0-9]{2}-){15,}[a-f0-9]{2}/giu;
const KEY_TEXT = /^[A-Z0-9]{32}$/u;
const IV_MARKER = "Wikipedia, the free";

export interface DarkwoodAnalysis {
  readonly sample_name: string;
  readonly bundle_version: string;
  readonly bundle_id: string;
  readonly assembly_path: string;
  readonly assembly_sha256: string;
  readonly algorithm: "AES-256-CBC-PKCS7";
  readonly key: string;
  readonly iv: string;
  readonly decrypted_secret: string;
}

function printable(value: string): boolean {
  return value.length > 0 && value.length <= 4096 && /^[\x20-\x7e]+$/u.test(value);
}

function extractedStrings(bytes: Buffer, minimum = 4): ReadonlyArray<string> {
  const found = new Set<string>();
  const ascii = bytes.toString("latin1").match(new RegExp(`[ -~]{${minimum},}`, "gu")) ?? [];
  for (const value of ascii) found.add(value);

  for (let offset = 0; offset < bytes.length - minimum * 2; offset += 1) {
    let cursor = offset;
    let value = "";
    while (
      cursor + 1 < bytes.length &&
      bytes[cursor]! >= 0x20 &&
      bytes[cursor]! <= 0x7e &&
      bytes[cursor + 1] === 0
    ) {
      value += String.fromCharCode(bytes[cursor]!);
      cursor += 2;
    }
    if (value.length >= minimum) {
      found.add(value);
      offset = cursor - 1;
    }
  }
  return [...found];
}

function only<T>(values: ReadonlyArray<T>, label: string): T {
  if (values.length !== 1) throw invalidInput(`Expected exactly one Darkwood ${label}.`);
  return values[0]!;
}

function appAssembly(
  entries: ReadonlyArray<DotnetBundleEntry>,
  sampleName: string,
): DotnetBundleEntry {
  const expected = `${sampleName.slice(0, -".exe".length)}.dll`;
  return only(
    entries.filter((entry) => entry.path === expected),
    `application assembly named ${expected}`,
  );
}

function analyzeDarkwoodAssembly(
  assembly: Buffer,
): Omit<
  DarkwoodAnalysis,
  "sample_name" | "bundle_version" | "bundle_id" | "assembly_path" | "assembly_sha256"
> {
  if (assembly.length < 128 || assembly.subarray(0, 2).toString("ascii") !== "MZ") {
    throw invalidInput("The Darkwood application entry is not a PE assembly.");
  }
  const strings = extractedStrings(assembly);
  const ciphertextCandidates = [
    ...new Set(strings.flatMap((value) => value.match(CIPHER_TEXT) ?? [])),
  ];
  const keyCandidates = strings.filter((value) => KEY_TEXT.test(value));
  const markerCandidates = strings.filter((value) => value.includes(IV_MARKER));
  const ciphertext = only(ciphertextCandidates, "ciphertext");
  const key = only(keyCandidates, "32-byte key");
  const marker = only(markerCandidates, "IV marker");
  const iv = marker.slice(marker.indexOf(IV_MARKER), marker.indexOf(IV_MARKER) + 16);
  if (Buffer.byteLength(iv, "utf8") !== 16) throw invalidInput("The Darkwood IV is invalid.");

  const cipherBytes = Buffer.from(ciphertext.replaceAll("-", ""), "hex");
  if (cipherBytes.length === 0 || cipherBytes.length % 16 !== 0) {
    throw invalidInput("The Darkwood ciphertext has an invalid AES block length.");
  }
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv("aes-256-cbc", Buffer.from(key), Buffer.from(iv));
    plaintext = Buffer.concat([decipher.update(cipherBytes), decipher.final()]);
  } catch (cause) {
    throw invalidInput("Darkwood AES decryption failed.", cause);
  }
  const decryptedSecret = plaintext.toString("utf8");
  if (!printable(decryptedSecret) || !Buffer.from(decryptedSecret).equals(plaintext)) {
    throw invalidInput("The Darkwood plaintext is not bounded printable UTF-8.");
  }
  return {
    algorithm: "AES-256-CBC-PKCS7",
    key,
    iv,
    decrypted_secret: decryptedSecret,
  };
}

/** Analyze a Darkwood apphost entirely as bytes; the apphost and assembly are never executed. */
export function analyzeDarkwoodSample(
  input: Uint8Array,
  sampleNameInput: string,
): DarkwoodAnalysis {
  const sampleName = path.basename(sampleNameInput);
  if (sampleName !== sampleNameInput || !DARKWOOD_SAMPLE.test(sampleName)) {
    throw invalidInput("The Darkwood sample name is invalid.");
  }
  const bundle = parseDotnetBundle(input, {
    maxBundleBytes: 96 * 1024 * 1024,
    maxEntries: 1024,
    maxEntryBytes: 128 * 1024 * 1024,
  });
  const entry = appAssembly(bundle.entries, sampleName);
  if (entry.size > 4 * 1024 * 1024) {
    throw invalidInput("The Darkwood application assembly exceeds the course limit.");
  }
  const assembly = extractDotnetBundleEntry(input, bundle, entry, {
    maxEntryBytes: 4 * 1024 * 1024,
  });
  return {
    sample_name: sampleName,
    bundle_version: `${bundle.majorVersion}.${bundle.minorVersion}`,
    bundle_id: bundle.bundleId,
    assembly_path: entry.path,
    assembly_sha256: createHash("sha256").update(assembly).digest("hex"),
    ...analyzeDarkwoodAssembly(assembly),
  };
}
