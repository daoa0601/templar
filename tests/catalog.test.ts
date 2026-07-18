import { describe, expect, it } from "vitest";

import {
  CAPABILITY_CLASSES,
  assertWorkflowAuthorized,
  requiresHumanAcknowledgment,
  workflowAdmission,
  workflowEntry,
  WORKFLOW_CATALOG,
} from "../src/catalog.js";

const WRITTEN_ROE = {
  engagementId: "ENG-2026-001",
  legalGrantor: "Authorized system owner",
  targetAllowlist: ["lab-target-01"],
  methodAllowlist: ["synthetic-validation"],
  exclusions: ["production", "real credentials"],
  startsAt: "2000-01-01T00:00:00.000Z",
  expiresAt: "2100-01-01T00:00:00.000Z",
  emergencyContact: "lab-owner@example.invalid",
  killSwitchConfirmed: true,
} as const;

describe("Templar workflow capability gates", () => {
  it("publishes the complete typed capability vocabulary and release catalog", () => {
    expect(CAPABILITY_CLASSES).toEqual([
      "PASSIVE_READ",
      "DEFENSIVE_ADVICE",
      "RE_STATIC",
      "RE_DYNAMIC_LAB",
      "ACTIVE_TEST",
    ]);
    expect(workflowEntry("telecom_incident")).toMatchObject({
      releaseState: "enabled",
      requiredCapability: "PASSIVE_READ",
      enabledByDefault: true,
      evaluatorRequired: true,
      traceAuditorRequired: true,
    });
    expect(workflowEntry("pcap_security_triage")).toMatchObject({
      agentOrganizationId: "pcap_security_triage",
      releaseState: "enabled",
      family: "blue_team",
      requiredCapability: "PASSIVE_READ",
      networkMode: "denied",
      evaluatorRequired: true,
      traceAuditorRequired: false,
    });
    expect(workflowEntry("exercise_solve")).toMatchObject({
      releaseState: "enabled",
      family: "reverse_engineering",
      requiredCapability: "RE_STATIC",
      networkMode: "denied",
      traceAuditorRequired: false,
    });
    expect(workflowEntry("course_assignment_evaluation")).toMatchObject({
      agentOrganizationId: "course_assignment_evaluation",
      releaseState: "enabled",
      family: "reverse_engineering",
      requiredCapability: "RE_STATIC",
      networkMode: "denied",
      traceAuditorRequired: true,
    });
    expect(workflowEntry("course_security_evaluation")).toMatchObject({
      agentOrganizationId: "course_security_evaluation",
      releaseState: "enabled",
      family: "reverse_engineering",
      requiredCapability: "RE_STATIC",
      networkMode: "denied",
      traceAuditorRequired: true,
    });
    expect(workflowEntry("source_security_audit")).toMatchObject({
      agentOrganizationId: "source_security_audit",
      releaseState: "enabled",
      family: "blue_team",
      requiredCapability: "RE_STATIC",
      networkMode: "denied",
      traceAuditorRequired: true,
    });
    expect(workflowEntry("source_security_fix")).toMatchObject({
      agentOrganizationId: "source_security_fix",
      releaseState: "enabled",
      family: "blue_team",
      requiredCapability: "RE_STATIC",
      networkMode: "denied",
      traceAuditorRequired: true,
    });
    expect(
      WORKFLOW_CATALOG.filter((entry) => entry.enabledByDefault).map((entry) => entry.id),
    ).toEqual([
      "telecom_incident",
      "pcap_security_triage",
      "exercise_solve",
      "course_assignment_evaluation",
      "course_security_evaluation",
      "source_security_audit",
      "source_security_fix",
    ]);
    expect(WORKFLOW_CATALOG.map((entry) => entry.id)).toEqual(
      expect.arrayContaining([
        "case.authorize",
        "evidence.register",
        "incident.reconstruct",
        "host.artifact_triage",
        "binary.static_pe",
        "binary.static_dotnet",
        "intel.ioc_graph",
        "detection.rule_draft",
        "containment.advise",
        "dynamic.plan",
        "sample.dynamic_observe",
        "sample.debug_unpack",
        "sample.dotnet_runtime",
        "network.c2_emulate",
        "redteam.exercise",
      ]),
    );
  });

  it("denies planned workflows and gates dynamic execution on a lab plus a human", () => {
    expect(
      workflowAdmission(workflowEntry("binary.static_pe"), {
        grantedCapabilities: ["RE_STATIC"],
      }),
    ).toMatchObject({ allowed: false, reasons: ["workflow_not_released"] });
    expect(
      workflowAdmission(workflowEntry("sample.dynamic_observe"), {
        grantedCapabilities: ["RE_DYNAMIC_LAB"],
      }),
    ).toMatchObject({
      allowed: false,
      reasons: ["human_approval_missing", "lab_attestation_missing"],
    });
    expect(() =>
      assertWorkflowAuthorized(workflowEntry("sample.dynamic_observe"), {
        grantedCapabilities: ["RE_DYNAMIC_LAB"],
        labAttested: true,
        humanApproved: true,
      }),
    ).not.toThrow();
  });

  it("keeps redteam.exercise disabled without written ROE and immediate human approval", () => {
    const active = workflowEntry("redteam.exercise");
    expect(workflowAdmission(active, { grantedCapabilities: ["ACTIVE_TEST"] }).allowed).toBe(false);
    expect(() =>
      assertWorkflowAuthorized(active, {
        grantedCapabilities: ["ACTIVE_TEST"],
        enableDisabledWorkflow: true,
        labAttested: true,
        humanApproved: true,
        writtenRoe: WRITTEN_ROE,
      }),
    ).not.toThrow();
  });

  it("requires acknowledgment for high-impact, security, headline, active, or degraded-audit outcomes", () => {
    expect(
      requiresHumanAcknowledgment({
        family: "red_team",
        severity: "high",
        securityOutcome: true,
        headlineResult: true,
        manualAuditRequired: true,
      }),
    ).toEqual([
      "active_security_result",
      "high_impact_result",
      "security_result",
      "headline_result",
      "manual_evaluation_audit",
    ]);
  });
});
