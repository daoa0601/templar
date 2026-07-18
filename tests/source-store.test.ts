import { mkdir, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { SourceSnapshotStore } from "../src/source-store.js";
import { decodeSourceSnapshot } from "../src/source.js";
import { sourceSnapshot } from "./source-fixture.js";
import { temporaryDirectory } from "./helpers.js";

function storedPath(root: string, artifactId: string): string {
  return path.join(root, `${artifactId.slice("source_sha256_".length)}.json`);
}

describe("SourceSnapshotStore", () => {
  it("deduplicates canonical snapshots and resolves verified bytes", async () => {
    const root = await temporaryDirectory("templar-source-store-");
    const store = new SourceSnapshotStore(root, 1024 * 1024);

    const [first, second] = await Promise.all([
      store.stage(sourceSnapshot()),
      store.stage(sourceSnapshot()),
    ]);

    expect(second).toEqual(first);
    expect(first).toMatchObject({
      artifact_id: expect.stringMatching(/^source_sha256_[a-f0-9]{64}$/u),
      digest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/u),
      media_type: "application/vnd.templar.source-snapshot+json",
    });
    expect(await store.resolve(first.artifact_id)).toEqual(decodeSourceSnapshot(sourceSnapshot()));
  });

  it("snapshots caller input and fails closed on a corrupted destination", async () => {
    const root = await temporaryDirectory("templar-source-corrupt-");
    const store = new SourceSnapshotStore(root, 1024 * 1024);
    const input = JSON.parse(JSON.stringify(sourceSnapshot())) as {
      files: Array<{ content: string }>;
    };

    const stagedPromise = store.stage(input);
    input.files[0]!.content = "changed after staging started";
    const staged = await stagedPromise;
    expect(
      (await store.resolve(staged.artifact_id)).files.find((file) => file.path === "src/app.ts")!
        .content,
    ).not.toBe("changed after staging started");

    const candidate = storedPath(root, staged.artifact_id);
    const corrupt = Buffer.from('{"corrupt":true}\n', "utf8");
    await writeFile(candidate, corrupt, { mode: 0o600 });
    await expect(store.resolve(staged.artifact_id)).rejects.toMatchObject({
      code: "SOURCE_INVALID",
      status: 400,
      message: "Source snapshot digest verification failed.",
    });
    await expect(store.stage(sourceSnapshot())).rejects.toMatchObject({
      code: "SOURCE_INVALID",
      status: 400,
      message: "Unable to stage source snapshot.",
    });
    expect(await readFile(candidate)).toEqual(corrupt);
  });

  it("distinguishes invalid IDs and absent snapshots from unsafe stored files", async () => {
    const root = await temporaryDirectory("templar-source-errors-");
    const store = new SourceSnapshotStore(root, 1024 * 1024);

    await expect(store.resolve("source_sha256_invalid")).rejects.toMatchObject({
      code: "SOURCE_INVALID",
      status: 400,
      message: "Invalid source snapshot ID.",
    });
    await expect(store.resolve(`source_sha256_${"a".repeat(64)}`)).rejects.toMatchObject({
      code: "NOT_FOUND",
      status: 404,
      message: "Source snapshot was not found.",
    });

    const staged = await store.stage(sourceSnapshot());
    const candidate = storedPath(root, staged.artifact_id);
    const outside = path.join(await temporaryDirectory("templar-source-outside-"), "data.json");
    await writeFile(outside, "{}\n", { mode: 0o600 });
    await unlink(candidate);
    await symlink(outside, candidate);
    await expect(store.resolve(staged.artifact_id)).rejects.toMatchObject({
      code: "SOURCE_INVALID",
      status: 400,
      message: "Source snapshot is not a regular file.",
    });
  });

  it("rejects a symbolic-link root without exposing its target path", async () => {
    const base = await temporaryDirectory("templar-source-root-");
    const target = path.join(base, "private-target");
    const symbolicRoot = path.join(base, "source-link");
    await mkdir(target, { mode: 0o700 });
    await symlink(target, symbolicRoot, "dir");
    const store = new SourceSnapshotStore(symbolicRoot, 1024 * 1024);

    let observed: unknown;
    try {
      await store.initialize();
    } catch (error) {
      observed = error;
    }
    expect(observed).toMatchObject({
      code: "SOURCE_INVALID",
      status: 400,
      message: "Configured source snapshot root must be a real directory.",
    });
    expect(String(observed)).not.toContain(target);
  });
});
