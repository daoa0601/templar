import { describe, expect, it } from "vitest";

import {
  parseSevenZipTechnicalList,
  sevenZipEnvironment,
  sevenZipExtractToStdoutArgs,
  sevenZipListArgs,
  sevenZipPasswordStdin,
} from "../src/seven-zip.js";

const LISTING = `Path = darkwood_A.exe
Size = 69154119
Packed Size = 123
Attributes = A
Encrypted = +
Block = 0

Path = nested/readme.txt
Size = 12
Packed Size =
Attributes = A
Encrypted = -
Block = 1
`;

describe("strict 7-Zip technical listings", () => {
  it("parses regular files and preserves archive order", () => {
    expect(parseSevenZipTechnicalList(LISTING)).toEqual([
      { path: "darkwood_A.exe", size: 69_154_119, encrypted: true, block: "0" },
      { path: "nested/readme.txt", size: 12, encrypted: false, block: "1" },
    ]);
  });

  it("rejects traversal, duplicate, malformed, and empty listings", () => {
    expect(() => parseSevenZipTechnicalList(LISTING.replace("nested/readme", "../readme"))).toThrow(
      /unsafe path segment/u,
    );
    expect(() => parseSevenZipTechnicalList(`${LISTING}\n${LISTING.split("\n\n", 1)[0]}`)).toThrow(
      /Duplicate 7-Zip member/u,
    );
    expect(() => parseSevenZipTechnicalList("Path = only-a-path")).toThrow(/invalid size/u);
    expect(() => parseSevenZipTechnicalList("")).toThrow(/empty or too large/u);
  });

  it("keeps passwords off argv and strips unrelated environment values", () => {
    expect(sevenZipPasswordStdin("course-password")).toBe("course-password\n");
    expect(sevenZipListArgs("/private/course.7z")).toEqual([
      "l",
      "-slt",
      "-ba",
      "--",
      "/private/course.7z",
    ]);
    expect(sevenZipExtractToStdoutArgs("/private/course.7z", [])).toEqual([
      "x",
      "-so",
      "--",
      "/private/course.7z",
    ]);
    expect(() => sevenZipPasswordStdin("line\nbreak")).toThrow(/password is invalid/u);
    expect(() => sevenZipPasswordStdin("")).toThrow(/password is invalid/u);
    expect(
      sevenZipEnvironment({ PATH: "/bin", TMPDIR: "/tmp", SECRET_TOKEN: "must-not-pass" }),
    ).toEqual({ PATH: "/bin", TMPDIR: "/tmp", LANG: "C", LC_ALL: "C" });
  });
});
