import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import { decodeDroneBaseUrl, DroneClient, droneUnavailableStatus } from "../src/drone-client.js";

describe("Drone client boundary", () => {
  it("allows loopback HTTP or HTTPS without embedded credentials and paths", () => {
    expect(decodeDroneBaseUrl("http://127.0.0.1:8090").origin).toBe("http://127.0.0.1:8090");
    expect(decodeDroneBaseUrl("https://drone.example").origin).toBe("https://drone.example");
    expect(() => decodeDroneBaseUrl("http://drone.example")).toThrow(/loopback HTTP/iu);
    expect(() => decodeDroneBaseUrl("https://user:secret@drone.example")).toThrow();
    expect(() => decodeDroneBaseUrl("https://drone.example/api")).toThrow();
  });

  it("authenticates and strictly decodes provider status", async () => {
    const request = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("authorization")).toBe("Bearer local-drone-token");
      return new Response(
        JSON.stringify([
          {
            provider_id: "apple_native",
            product: "Apple Containerization",
            installed: true,
            enabled: true,
            mutations_available: true,
            reason: "ready",
            isolation: "lightweight_vm",
            guest_os: ["linux"],
            network_modes: ["none"],
          },
        ]),
        { headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new DroneClient({
      baseUrl: "http://127.0.0.1:8090",
      token: "local-drone-token",
      timeoutMs: 100,
      fetch: request,
    });
    await expect(client.providers()).resolves.toEqual([
      expect.objectContaining({ provider_id: "apple_native", network_modes: ["none"] }),
    ]);
  });

  it("submits only declared operation IDs and content-addressed inputs", async () => {
    const request = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      expect(JSON.parse(String(init?.body))).toEqual({
        schema_version: "1",
        operation_id: "pe.static_snapshot",
        inputs: { sample: `sha256_${"a".repeat(64)}` },
      });
      return new Response(
        JSON.stringify({
          schema_version: "1",
          job_id: `job_${"b".repeat(32)}`,
          operation_id: "pe.static_snapshot",
          provider_id: "apple_native",
          status: "queued",
          inputs: { sample: `sha256_${"a".repeat(64)}` },
          outputs: [],
          submitted_at: "2026-07-18T08:31:00.000Z",
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new DroneClient({
      baseUrl: "http://127.0.0.1:8090",
      timeoutMs: 100,
      fetch: request,
    });

    await expect(
      client.submitJob({
        schema_version: "1",
        operation_id: "pe.static_snapshot",
        inputs: { sample: `sha256_${"a".repeat(64)}` },
      }),
    ).resolves.toMatchObject({ status: "queued" });
    await expect(
      client.submitJob({ schema_version: "1", operation_id: "../escape", inputs: {} }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
    await expect(
      client.submitJob({
        schema_version: "1",
        operation_id: "pe.static_snapshot",
        inputs: { sample: "mutable-file-name" },
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });

  it("discovers operations, stages correlated artifacts, and reads one correlated job", async () => {
    const bytes = Buffer.from("bounded source tree");
    const digest = createHash("sha256").update(bytes).digest("hex");
    const artifactId = `sha256_${digest}`;
    const jobId = `job_${"c".repeat(32)}`;
    const operation = {
      operation_id: "source.validate",
      enabled: true,
      provider: "apple_native",
      architecture: "arm64",
      network: "none",
      inputs: [
        {
          name: "source",
          required: true,
          max_bytes: 1024,
          media_types: ["application/vnd.templar.source-tree+json"],
        },
      ],
      outputs: [
        {
          name: "validation",
          required: true,
          max_bytes: 1024,
          media_type: "application/json",
        },
      ],
      resources: {
        cpus: 1,
        memory_mb: 512,
        rootfs_mb: 1024,
        writable_mb: 128,
        output_disk_mb: 64,
        timeout_seconds: 60,
        max_log_bytes: 4096,
        max_processes: 64,
        max_open_files: 64,
      },
    };
    const request = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(input);
      if (url.pathname === "/v1/operations") {
        return new Response(JSON.stringify([operation]), {
          headers: { "Content-Type": "application/json" },
        });
      }
      if (url.pathname === "/v1/artifacts") {
        expect(init?.method).toBe("POST");
        expect(Buffer.from(init?.body as ArrayBuffer).equals(bytes)).toBe(true);
        return new Response(
          JSON.stringify({
            schema_version: "1",
            artifact_id: artifactId,
            sha256: digest,
            size_bytes: bytes.byteLength,
            media_type: "application/vnd.templar.source-tree+json",
            created_at: "2026-07-18T08:30:00.000Z",
          }),
          { headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({
          schema_version: "1",
          job_id: jobId,
          operation_id: "source.validate",
          provider_id: "apple_native",
          status: "running",
          inputs: { source: artifactId },
          outputs: [],
          submitted_at: "2026-07-18T08:31:00.000Z",
          started_at: "2026-07-18T08:31:01.000Z",
        }),
        { headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new DroneClient({
      baseUrl: "http://127.0.0.1:8090",
      timeoutMs: 100,
      fetch: request,
    });
    await expect(client.operations()).resolves.toEqual([operation]);
    await expect(
      client.stageArtifact(bytes, "application/vnd.templar.source-tree+json"),
    ).resolves.toMatchObject({ artifact_id: artifactId });
    await expect(client.job(jobId)).resolves.toMatchObject({ job_id: jobId, status: "running" });
  });

  it.each([
    ["wrong content type", new Response("{}", { headers: { "Content-Type": "text/plain" } })],
    [
      "declared oversized response",
      new Response("[]", {
        headers: { "Content-Type": "application/json", "Content-Length": "999999" },
      }),
    ],
    ["invalid JSON", new Response("not-json", { headers: { "Content-Type": "application/json" } })],
  ])("fails closed on %s", async (_label, response) => {
    const client = new DroneClient({
      baseUrl: "http://127.0.0.1:8090",
      timeoutMs: 100,
      fetch: async () => response,
    });
    await expect(client.providers()).rejects.toMatchObject({ code: "SERVICE_UNAVAILABLE" });
  });

  it("uses an explicit fail-closed status when Drone is not reachable", () => {
    expect(droneUnavailableStatus("service_unavailable")).toMatchObject({
      provider_id: "drone",
      enabled: false,
      mutations_available: false,
      reason: "service_unavailable",
    });
  });
});
