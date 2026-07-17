import { symlink, writeFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { ParallelsDesktopCommandPlanner, parallelsDesktopStatus } from "../src/lab-provider.js";
import { temporaryDirectory } from "./helpers.js";

const BASE_VM = "123e4567-e89b-42d3-a456-426614174000";
const SNAPSHOT = "123e4567-e89b-42d3-a456-426614174001";
const LAB = "123e4567-e89b-42d3-a456-426614174002";

describe("Parallels Desktop provider boundary", () => {
  it("reports installation without querying VM inventory", async () => {
    const root = await temporaryDirectory("templar-parallels-");
    const cliPath = path.join(root, "prlctl");
    await writeFile(cliPath, "fixture", "utf8");
    await expect(
      parallelsDesktopStatus({ enabled: false, cliPath, quarantineRoot: path.join(root, "labs") }),
    ).resolves.toEqual({
      provider_id: "parallels_desktop",
      product: "Parallels Desktop",
      installed: true,
      enabled: false,
      mutations_available: false,
      reason: "disabled_by_configuration",
    });
  });

  it("does not report a broken CLI symlink as installed", async () => {
    const root = await temporaryDirectory("templar-parallels-broken-");
    const cliPath = path.join(root, "prlctl");
    await symlink(path.join(root, "missing-prlctl"), cliPath);
    await expect(
      parallelsDesktopStatus({ enabled: true, cliPath, quarantineRoot: path.join(root, "labs") }),
    ).resolves.toMatchObject({ installed: false, enabled: false, mutations_available: false });
  });

  it("refuses every mutating plan while disabled", () => {
    const planner = new ParallelsDesktopCommandPlanner({
      enabled: false,
      cliPath: "/usr/local/bin/prlctl",
      quarantineRoot: "/var/tmp/templar-labs",
    });
    expect(() =>
      planner.cloneFromSnapshot({ runId: "run-1", baseVmId: BASE_VM, snapshotId: SNAPSHOT }),
    ).toThrow(/disabled/iu);
  });

  it("builds fixed shell-free argv from trusted IDs only", () => {
    const planner = new ParallelsDesktopCommandPlanner({
      enabled: true,
      cliPath: "/Applications/Parallels Desktop.app/Contents/MacOS/prlctl",
      quarantineRoot: "/var/tmp/templar-labs",
    });
    const clone = planner.cloneFromSnapshot({
      runId: "exercise-run-1",
      baseVmId: BASE_VM,
      snapshotId: SNAPSHOT,
    });
    expect(clone.labName).toMatch(/^templar-[a-f0-9]{20}$/u);
    expect(clone.plan).toMatchObject({ operation: "clone", mutating: true });
    expect(clone.plan.args.slice(0, 4)).toEqual(["clone", BASE_VM, "--name", clone.labName]);
    expect(planner.execute(LAB, "exercise.static_pe_snapshot").args).toEqual([
      "exec",
      LAB,
      "C:\\Templar\\capture-static-pe.cmd",
    ]);
    expect(planner.stop(LAB, true).args).toEqual(["stop", LAB, "--kill"]);
    expect(() => planner.start("not-a-vm")).toThrow(/UUID/iu);
  });
});
