import { defineAgentOrganization } from "@agentic-orch/agent-blocks";
import type {
  AgentRuntime,
  RuntimeTurnInput,
  RuntimeTurnResult,
  SupervisorDecision,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";

import { SecurityTeamRuntime, securityTeamPhases } from "../src/security-team-guard.js";
import {
  COURSE_ASSIGNMENT_EVALUATION_TEAM_PLAN,
  COURSE_SECURITY_EVALUATION_TEAM_PLAN,
  PCAP_SECURITY_TRIAGE_TEAM_PLAN,
  SOURCE_SECURITY_AUDIT_TEAM_PLAN,
} from "../src/security-teams.js";
import type { SecurityRoleBlock, SecurityTeamPlan } from "../src/security-teams.js";

const SUPERVISOR_INPUT: RuntimeTurnInput = {
  agentId: "supervisor",
  cwd: "/tmp/templar-security-team-guard-test",
  sandbox: "read-only",
  prompt: "bounded test prompt",
  threadId: undefined,
  model: undefined,
  outputSchemaPath: "/tmp/supervisor.schema.json",
  timeoutSeconds: 10,
};

function result(decision: SupervisorDecision): RuntimeTurnResult {
  return {
    threadId: "supervisor-thread",
    finalText: JSON.stringify(decision),
    usage: { inputTokens: 1, cachedInputTokens: 0, outputTokens: 1, totalTokens: 2 },
    events: [],
  };
}

function continuing(assignments: SupervisorDecision["assignments"]): RuntimeTurnResult {
  return result({
    status: "continue",
    summary: "Dispatch the next bounded phase.",
    assignments,
    selectedCandidateId: null,
  });
}

const ACCEPTING = result({
  status: "accept",
  summary: "Accept the evaluator-selected candidate.",
  assignments: [],
  selectedCandidateId: "candidate_a",
});

class SequenceRuntime implements AgentRuntime {
  readonly #outputs: ReadonlyArray<RuntimeTurnResult>;
  readonly inputs: Array<RuntimeTurnInput> = [];
  #index = 0;

  constructor(outputs: ReadonlyArray<RuntimeTurnResult>) {
    this.#outputs = outputs;
  }

  readonly runTurn = (input: RuntimeTurnInput) => {
    this.inputs.push(input);
    const output = this.#outputs[this.#index];
    this.#index += 1;
    return output === undefined ? Effect.die("Sequence runtime exhausted") : Effect.succeed(output);
  };
}

async function supervisorTurn(runtime: AgentRuntime): Promise<RuntimeTurnResult> {
  return Effect.runPromise(runtime.runTurn(SUPERVISOR_INPUT));
}

function decision(output: RuntimeTurnResult): SupervisorDecision {
  return JSON.parse(output.finalText) as SupervisorDecision;
}

function oneBlockPlan(block: SecurityRoleBlock): SecurityTeamPlan {
  return defineAgentOrganization<SecurityRoleBlock>({
    id: "guard_test",
    teams: [
      {
        id: "assurance_team",
        members: [{ id: "member", blocks: [block] }],
      },
    ],
  });
}

describe("Templar security-team runtime guard", () => {
  it("dispatches complete phases to their declared member owners", async () => {
    const delegate = new SequenceRuntime([
      continuing([
        {
          agentId: "research_once",
          roleId: "security_evidence_researcher",
          task: "Prioritize packet facts.",
          targetCandidateId: null,
        },
      ]),
      continuing([
        {
          agentId: "candidate_b",
          roleId: "security_analyst",
          task: "Independently analyze the bounded evidence.",
          targetCandidateId: null,
        },
        {
          agentId: "candidate_a",
          roleId: "security_analyst",
          task: "Analyze the bounded evidence.",
          targetCandidateId: null,
        },
      ]),
      ACCEPTING,
    ]);
    const runtime = new SecurityTeamRuntime(delegate, PCAP_SECURITY_TRIAGE_TEAM_PLAN);

    const first = await supervisorTurn(runtime);
    expect(delegate.inputs[0]?.prompt).toContain(
      'Phase 1 roster: [{"agentId":"research_once","roleId":"security_evidence_researcher","targetCandidateId":null}]',
    );
    expect(first.events).toContainEqual({
      type: "templar.security_team_assignment",
      organizationId: "pcap_security_triage",
      phase: 1,
      assignments: [
        {
          blockId: "pcap_evidence_research",
          teamId: "purple_team",
          memberId: "packet_evidence_coordinator",
          agentId: "research_once",
          roleId: "security_evidence_researcher",
          targetCandidateId: null,
        },
      ],
    });
    expect(decision(await supervisorTurn(runtime)).status).toBe("continue");
    expect(delegate.inputs[1]?.prompt).toContain(
      'Phase 2 roster: [{"agentId":"candidate_a","roleId":"security_analyst","targetCandidateId":null},{"agentId":"candidate_b","roleId":"security_analyst","targetCandidateId":null}]',
    );
    expect(decision(await supervisorTurn(runtime))).toMatchObject({
      status: "accept",
      selectedCandidateId: "candidate_a",
    });
  });

  it("stops invented members, skipped phases, and early acceptance", async () => {
    const invented = new SecurityTeamRuntime(
      new SequenceRuntime([
        continuing([
          {
            agentId: "unplanned_agent",
            roleId: "security_evidence_researcher",
            task: "Attempt an undeclared assignment.",
            targetCandidateId: null,
          },
        ]),
      ]),
      PCAP_SECURITY_TRIAGE_TEAM_PLAN,
    );
    const inventedOutput = await supervisorTurn(invented);
    expect(decision(inventedOutput)).toMatchObject({
      status: "stop",
      summary: expect.stringContaining("does not authorize unplanned_agent"),
    });
    expect(inventedOutput.events).toContainEqual(
      expect.objectContaining({
        type: "templar.security_team_guard",
        disposition: "stopped",
      }),
    );

    const skipped = new SecurityTeamRuntime(
      new SequenceRuntime([
        continuing([
          {
            agentId: "candidate_a",
            roleId: "security_analyst",
            task: "Attempt to skip evidence coordination.",
            targetCandidateId: null,
          },
          {
            agentId: "candidate_b",
            roleId: "security_analyst",
            task: "Attempt to skip evidence coordination.",
            targetCandidateId: null,
          },
        ]),
      ]),
      PCAP_SECURITY_TRIAGE_TEAM_PLAN,
    );
    expect(decision(await supervisorTurn(skipped)).summary).toContain(
      "phase 1 requires 1 assignments, received 2",
    );

    const early = new SecurityTeamRuntime(
      new SequenceRuntime([ACCEPTING]),
      PCAP_SECURITY_TRIAGE_TEAM_PLAN,
    );
    expect(decision(await supervisorTurn(early)).summary).toContain(
      "acceptance requested before phase 1",
    );
  });

  it("requires exact roles and pinned review targets", async () => {
    const reviewPlan = oneBlockPlan({
      id: "pinned_review",
      phase: 1,
      agentId: "audit_a",
      targetCandidateId: "candidate_a",
      role: {
        id: "evaluation_auditor",
        kind: "review",
        description: "Audit one pinned candidate.",
        instructions: "Read only.",
        maxInstances: 1,
        maxTurns: 1,
        model: undefined,
      },
    });
    const runtime = new SecurityTeamRuntime(
      new SequenceRuntime([
        continuing([
          {
            agentId: "audit_a",
            roleId: "evaluation_auditor",
            task: "Audit a different candidate.",
            targetCandidateId: "candidate_b",
          },
        ]),
      ]),
      reviewPlan,
    );

    expect(decision(await supervisorTurn(runtime)).summary).toContain(
      "expected audit_a:evaluation_auditor:candidate_a",
    );
  });

  it("binds pinned-review tasks to the block evidence boundary", async () => {
    const reviewPlan = oneBlockPlan({
      id: "pinned_review",
      phase: 1,
      agentId: "audit_a",
      targetCandidateId: "candidate_a",
      role: {
        id: "evaluation_auditor",
        kind: "review",
        description: "Audit one pinned candidate.",
        instructions: "Read only.",
        maxInstances: 1,
        maxTurns: 1,
        model: undefined,
      },
    });
    const runtime = new SecurityTeamRuntime(
      new SequenceRuntime([
        continuing([
          {
            agentId: "audit_a",
            roleId: "evaluation_auditor",
            task: "Require inaccessible coordinator and red-team reports before passing.",
            targetCandidateId: "candidate_a",
          },
        ]),
      ]),
      reviewPlan,
    );

    const output = await supervisorTurn(runtime);
    const bound = decision(output);
    expect(bound.status).toBe("continue");
    expect(bound.assignments[0]?.task).toContain("Audit only pinned candidate candidate_a");
    expect(bound.assignments[0]?.task).toContain(
      "Do not require or access coordinator, specialist, or other candidate reports",
    );
    expect(bound.assignments[0]?.task).not.toContain("before passing");
    expect(output.events).toContainEqual({
      type: "templar.security_team_task_bound",
      organizationId: "guard_test",
      phase: 1,
      blockId: "pinned_review",
      agentId: "audit_a",
      roleId: "evaluation_auditor",
      targetCandidateId: "candidate_a",
      policy: "pinned_review_evidence_only",
    });
  });

  it("validates phase continuity, unique logical agents, review targets, and role capacity", () => {
    const baseRole = {
      id: "researcher",
      kind: "research" as const,
      description: "Read-only research.",
      instructions: "Read only.",
      maxInstances: 1,
      maxTurns: 1,
      model: undefined,
    };
    const organization = (blocks: ReadonlyArray<SecurityRoleBlock>) =>
      defineAgentOrganization<SecurityRoleBlock>({
        id: "invalid",
        teams: [{ id: "red_team", members: [{ id: "member", blocks }] }],
      });

    expect(() =>
      securityTeamPhases(
        organization([
          { id: "first", phase: 1, agentId: "same", role: baseRole },
          { id: "second", phase: 2, agentId: "same", role: baseRole },
        ]),
      ),
    ).toThrow(/duplicate agent id same/u);
    expect(() =>
      securityTeamPhases(
        organization([
          {
            id: "first",
            phase: 1,
            agentId: "first",
            role: { ...baseRole, maxInstances: 2 },
          },
          {
            id: "third",
            phase: 3,
            agentId: "third",
            role: { ...baseRole, maxInstances: 2 },
          },
        ]),
      ),
    ).toThrow(/missing phase 2/u);
    expect(() =>
      securityTeamPhases(
        oneBlockPlan({
          id: "review_without_target",
          phase: 1,
          agentId: "audit",
          role: { ...baseRole, id: "reviewer", kind: "review" },
        }),
      ),
    ).toThrow(/invalid review target/u);
    expect(() =>
      securityTeamPhases(
        organization([
          { id: "first", phase: 1, agentId: "first", role: baseRole },
          { id: "second", phase: 1, agentId: "second", role: baseRole },
        ]),
      ),
    ).toThrow(/requires 2 instances but allows 1/u);

    expect(securityTeamPhases(SOURCE_SECURITY_AUDIT_TEAM_PLAN).map((phase) => phase.phase)).toEqual(
      [1, 2, 3, 4],
    );
    expect(
      securityTeamPhases(COURSE_ASSIGNMENT_EVALUATION_TEAM_PLAN).map((phase) => [
        phase.phase,
        phase.assignments.length,
      ]),
    ).toEqual([
      [1, 1],
      [2, 1],
      [3, 2],
      [4, 2],
    ]);
    expect(
      securityTeamPhases(COURSE_SECURITY_EVALUATION_TEAM_PLAN).map((phase) => [
        phase.phase,
        phase.assignments.length,
      ]),
    ).toEqual([
      [1, 1],
      [2, 4],
      [3, 2],
      [4, 2],
    ]);
  });
});
