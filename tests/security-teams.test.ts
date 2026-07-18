import { agentBlockAssignments, defineAgentOrganization } from "@agentic-orch/agent-blocks";
import { describe, expect, it } from "vitest";

import {
  PCAP_SECURITY_TRIAGE_TEAM_PLAN,
  rolesForSecurityTeamPlan,
  SECURITY_TEAM_IDS,
  securityRoleAssignment,
  securityTeamPlan,
  SOURCE_SECURITY_AUDIT_TEAM_PLAN,
  SOURCE_SECURITY_FIX_TEAM_PLAN,
} from "../src/security-teams.js";
import type { SecurityRoleBlock, SecurityTeamPlan } from "../src/security-teams.js";
import {
  pcapSecurityTriageWorkflow,
  sourceSecurityAuditWorkflow,
  sourceSecurityFixWorkflow,
} from "../src/workflow.js";
import type {
  PcapSecurityTriageWorkspace,
  SourceSecurityAuditWorkspace,
  SourceSecurityFixWorkspace,
} from "../src/workspace.js";

describe("Templar security team composition", () => {
  it("assigns source-audit blocks to concrete red, blue, purple, and assurance members", () => {
    expect(
      agentBlockAssignments(SOURCE_SECURITY_AUDIT_TEAM_PLAN).map((assignment) => [
        assignment.teamId,
        assignment.memberId,
        assignment.block.id,
        assignment.block.agentId,
        assignment.block.role.id,
        assignment.block.targetCandidateId ?? null,
      ]),
    ).toEqual([
      [
        "purple_team",
        "attack_surface_coordinator",
        "source_recon",
        "recon_once",
        "source_recon",
        null,
      ],
      [
        "red_team",
        "injection_specialist",
        "source_injection_hunt",
        "injection_once",
        "injection_hunter",
        null,
      ],
      [
        "red_team",
        "boundary_specialist",
        "source_boundary_hunt",
        "boundary_once",
        "boundary_hunter",
        null,
      ],
      [
        "red_team",
        "authorization_specialist",
        "source_authorization_hunt",
        "authorization_once",
        "authorization_hunter",
        null,
      ],
      [
        "blue_team",
        "finding_falsifier_a",
        "source_falsification_a",
        "candidate_a",
        "source_falsifier",
        null,
      ],
      [
        "blue_team",
        "finding_falsifier_b",
        "source_falsification_b",
        "candidate_b",
        "source_falsifier",
        null,
      ],
      [
        "assurance_team",
        "evaluation_auditor_a",
        "source_evaluation_audit_a",
        "audit_a",
        "evaluation_auditor",
        "candidate_a",
      ],
      [
        "assurance_team",
        "evaluation_auditor_b",
        "source_evaluation_audit_b",
        "audit_b",
        "evaluation_auditor",
        "candidate_b",
      ],
    ]);
  });

  it("drives the scoped role catalog and logical IDs from each team plan", () => {
    const pcap = pcapSecurityTriageWorkflow({
      root: "/pcap",
      evaluatorPath: "/pcap/evaluate.mjs",
    } as PcapSecurityTriageWorkspace);
    const audit = sourceSecurityAuditWorkflow({
      root: "/audit",
      evaluatorPath: "/audit/evaluate.mjs",
    } as SourceSecurityAuditWorkspace);
    const fix = sourceSecurityFixWorkflow({
      root: "/fix",
      evaluatorPath: "/fix/evaluate.mjs",
    } as SourceSecurityFixWorkspace);

    expect(pcap.roles).toEqual(rolesForSecurityTeamPlan(PCAP_SECURITY_TRIAGE_TEAM_PLAN));
    expect(audit.roles).toEqual(rolesForSecurityTeamPlan(SOURCE_SECURITY_AUDIT_TEAM_PLAN));
    expect(fix.roles).toEqual(rolesForSecurityTeamPlan(SOURCE_SECURITY_FIX_TEAM_PLAN));
    expect(pcap.supervisor.instructions).toContain("research_once");
    expect(audit.supervisor.instructions).toContain("authorization_once");
    expect(fix.supervisor.instructions).toContain("audit_b to candidate_b");
    expect(rolesForSecurityTeamPlan(SOURCE_SECURITY_AUDIT_TEAM_PLAN)).toHaveLength(6);
    expect(rolesForSecurityTeamPlan(SOURCE_SECURITY_FIX_TEAM_PLAN)).toHaveLength(3);
  });

  it("publishes the complete team vocabulary and plan lookup", () => {
    expect(SECURITY_TEAM_IDS).toEqual([
      "red_team",
      "blue_team",
      "purple_team",
      "assurance_team",
      "reverse_engineering_team",
      "network_analysis_team",
    ]);
    expect(securityTeamPlan("pcap_security_triage")).toBe(PCAP_SECURITY_TRIAGE_TEAM_PLAN);
    expect(
      securityRoleAssignment(SOURCE_SECURITY_FIX_TEAM_PLAN, "source_fix_audit_a").block,
    ).toMatchObject({
      agentId: "audit_a",
      targetCandidateId: "candidate_a",
      phase: 3,
    });
    expect(() => securityTeamPlan("missing")).toThrow(/No security team plan/u);
    expect(() => securityRoleAssignment(SOURCE_SECURITY_FIX_TEAM_PLAN, "missing")).toThrow(
      /has no block/u,
    );
  });

  it("rejects conflicting role definitions shared by separate members", () => {
    const role = {
      id: "shared_role",
      kind: "research" as const,
      description: "First definition.",
      instructions: "Read only.",
      maxInstances: 2,
      maxTurns: 1,
      model: undefined,
    };
    const conflicting = defineAgentOrganization<SecurityRoleBlock>({
      id: "conflicting",
      teams: [
        {
          id: "red_team",
          members: [
            {
              id: "first",
              blocks: [{ id: "first_block", phase: 1, agentId: "first", role }],
            },
            {
              id: "second",
              blocks: [
                {
                  id: "second_block",
                  phase: 1,
                  agentId: "second",
                  role: { ...role, description: "Conflicting definition." },
                },
              ],
            },
          ],
        },
      ],
    }) as SecurityTeamPlan;

    expect(() => rolesForSecurityTeamPlan(conflicting)).toThrow(/conflicting role shared_role/u);
  });
});
