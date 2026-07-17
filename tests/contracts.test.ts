import { describe, expect, it } from "vitest";

import { decodeIncidentInput, MAX_INCIDENT_TEXT } from "../src/contracts.js";

describe("IncidentInput v1", () => {
  it("decodes the bounded supported shape", () => {
    expect(
      decodeIncidentInput({
        schema_version: "1",
        request: "Investigate packet loss",
        observations: [
          { observation_id: "loss-rate", kind: "operator_metric", value: 2.5, unit: "percent" },
        ],
        ticket_ref: "NET-42",
        reported_priority: "P2",
        pcap_artifact_id: `pcap_sha256_${"a".repeat(64)}`,
      }),
    ).toMatchObject({ request: "Investigate packet loss", ticket_ref: "NET-42" });
  });

  it.each([
    [{ schema_version: "1", request: "" }, "empty"],
    [{ schema_version: "1", request: "x".repeat(MAX_INCIDENT_TEXT + 1) }, "oversized"],
    [{ schema_version: "1", request: "Read https://example.test" }, "URL"],
    [{ schema_version: "1", request: "Read /etc/passwd" }, "host path"],
    [{ schema_version: "1", request: "Read /workspace/private" }, "arbitrary absolute path"],
    [{ schema_version: "1", request: "Read ../private" }, "relative host path"],
    [{ schema_version: "1", request: "x", workspace: "/tmp/run" }, "workspace"],
    [{ schema_version: "1", request: "x", max_tokens: 999 }, "budget"],
    [{ schema_version: "1", request: "x", evaluator: "custom" }, "evaluator"],
    [{ schema_version: "1", request: "x", ticket_ref: "../../NET-1" }, "ticket"],
    [{ schema_version: "1", request: "x", pcap_artifact_id: "capture.pcap" }, "artifact"],
  ])("rejects %s (%s)", (input, _label) => {
    expect(() => decodeIncidentInput(input)).toThrow();
  });

  it("rejects nested unknown observation fields and non-primitive values", () => {
    expect(() =>
      decodeIncidentInput({
        schema_version: "1",
        request: "x",
        observations: [{ observation_id: "a", kind: "note", value: "ok", path: "/tmp/a" }],
      }),
    ).toThrow();
    expect(() =>
      decodeIncidentInput({
        schema_version: "1",
        request: "x",
        observations: [{ observation_id: "a", kind: "note", value: { command: "run" } }],
      }),
    ).toThrow();
  });
});
