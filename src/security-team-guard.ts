import { agentBlockAssignments } from "@agentic-orch/agent-blocks";
import type { AgentBlockAssignment } from "@agentic-orch/agent-blocks";
import { decodeSupervisorDecision } from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import type {
  AgentRuntime,
  Assignment,
  RuntimeTurnInput,
  RuntimeTurnResult,
  SupervisorDecision,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import { Effect } from "effect";

import type {
  SecurityRoleAssignment,
  SecurityRoleBlock,
  SecurityTeamPlan,
} from "./security-teams.js";

export interface SecurityTeamPhase {
  readonly phase: number;
  readonly assignments: ReadonlyArray<SecurityRoleAssignment>;
}

function describeAssignment(assignment: Assignment): string {
  return `${assignment.agentId}:${assignment.roleId}:${assignment.targetCandidateId ?? "none"}`;
}

function describePlannedAssignment(assignment: SecurityRoleAssignment): string {
  return `${assignment.block.agentId}:${assignment.block.role.id}:${assignment.block.targetCandidateId ?? "none"}`;
}

/** Compile and validate the deterministic execution phases owned by a security-team plan. */
export function securityTeamPhases(plan: SecurityTeamPlan): ReadonlyArray<SecurityTeamPhase> {
  const assignments = agentBlockAssignments(plan);
  const agentIds = new Set<string>();
  const roleInstances = new Map<string, number>();
  const phases = new Map<number, Array<AgentBlockAssignment<SecurityRoleBlock>>>();

  for (const assignment of assignments) {
    const { block } = assignment;
    if (!Number.isSafeInteger(block.phase) || block.phase <= 0) {
      throw new Error(`Security team plan ${plan.id} block ${block.id} has invalid phase`);
    }
    if (agentIds.has(block.agentId)) {
      throw new Error(`Security team plan ${plan.id} has duplicate agent id ${block.agentId}`);
    }
    agentIds.add(block.agentId);

    const hasTarget = block.targetCandidateId !== undefined;
    if ((block.role.kind === "review") !== hasTarget) {
      throw new Error(
        `Security team plan ${plan.id} block ${block.id} has an invalid review target`,
      );
    }

    roleInstances.set(block.role.id, (roleInstances.get(block.role.id) ?? 0) + 1);
    const phase = phases.get(block.phase) ?? [];
    phase.push(assignment);
    phases.set(block.phase, phase);
  }

  for (const assignment of assignments) {
    const instances = roleInstances.get(assignment.block.role.id) ?? 0;
    if (instances > assignment.block.role.maxInstances) {
      throw new Error(
        `Security team plan ${plan.id} role ${assignment.block.role.id} requires ${instances} instances but allows ${assignment.block.role.maxInstances}`,
      );
    }
  }

  const maxPhase = Math.max(...phases.keys());
  return Array.from({ length: maxPhase }, (_, index) => {
    const phase = index + 1;
    const planned = phases.get(phase);
    if (planned === undefined) {
      throw new Error(`Security team plan ${plan.id} is missing phase ${phase}`);
    }
    return { phase, assignments: planned };
  });
}

function phaseMismatch(
  phase: SecurityTeamPhase,
  assignments: ReadonlyArray<Assignment>,
): string | undefined {
  const expected = new Map(
    phase.assignments.map((assignment) => [assignment.block.agentId, assignment] as const),
  );
  if (assignments.length !== expected.size) {
    return `phase ${phase.phase} requires ${expected.size} assignments, received ${assignments.length}`;
  }

  const received = new Set<string>();
  for (const assignment of assignments) {
    if (received.has(assignment.agentId)) {
      return `phase ${phase.phase} repeats agent ${assignment.agentId}`;
    }
    received.add(assignment.agentId);
    const planned = expected.get(assignment.agentId);
    if (planned === undefined) {
      return `phase ${phase.phase} does not authorize ${describeAssignment(assignment)}`;
    }
    if (
      assignment.roleId !== planned.block.role.id ||
      (assignment.targetCandidateId ?? undefined) !== planned.block.targetCandidateId
    ) {
      return `phase ${phase.phase} expected ${describePlannedAssignment(planned)}, received ${describeAssignment(assignment)}`;
    }
  }
  return undefined;
}

function stoppedResult(
  output: RuntimeTurnResult,
  plan: SecurityTeamPlan,
  reason: string,
): RuntimeTurnResult {
  const decision: SupervisorDecision = {
    status: "stop",
    summary: `Templar security-team guard stopped the run: ${reason}.`,
    assignments: [],
    selectedCandidateId: null,
  };
  return {
    ...output,
    finalText: JSON.stringify(decision),
    events: [
      ...output.events,
      {
        type: "templar.security_team_guard",
        organizationId: plan.id,
        disposition: "stopped",
        reason,
      },
    ],
  };
}

/**
 * Fail-closed runtime boundary that binds supervisor assignments to declared team members.
 *
 * A continue decision must dispatch the complete next phase with the exact logical agent, role, and
 * review target declared by the owning block. Stopping early remains safe; acceptance is permitted
 * only after every phase has been dispatched.
 */
export class SecurityTeamRuntime implements AgentRuntime {
  readonly #delegate: AgentRuntime;
  readonly #plan: SecurityTeamPlan;
  readonly #phases: ReadonlyArray<SecurityTeamPhase>;
  readonly metadata?: NonNullable<AgentRuntime["metadata"]>;
  #nextPhaseIndex = 0;

  constructor(delegate: AgentRuntime, plan: SecurityTeamPlan) {
    this.#delegate = delegate;
    this.#plan = plan;
    this.#phases = securityTeamPhases(plan);
    if (delegate.metadata !== undefined) this.metadata = delegate.metadata;
  }

  readonly runTurn = (input: RuntimeTurnInput) =>
    this.#delegate.runTurn(input).pipe(
      Effect.map((output) => {
        if (input.agentId !== "supervisor") return output;

        let decision: SupervisorDecision;
        try {
          decision = decodeSupervisorDecision(JSON.parse(output.finalText));
        } catch {
          // The harness decoder will reject malformed supervisor output after this runtime boundary.
          return output;
        }

        if (decision.status === "stop") return output;
        if (decision.status === "accept") {
          return this.#nextPhaseIndex === this.#phases.length
            ? output
            : stoppedResult(
                output,
                this.#plan,
                `acceptance requested before phase ${this.#nextPhaseIndex + 1}`,
              );
        }

        const phase = this.#phases[this.#nextPhaseIndex];
        if (phase === undefined) {
          return stoppedResult(output, this.#plan, "no undispatched phase remains");
        }
        const mismatch = phaseMismatch(phase, decision.assignments);
        if (mismatch !== undefined) return stoppedResult(output, this.#plan, mismatch);

        this.#nextPhaseIndex += 1;
        return {
          ...output,
          events: [
            ...output.events,
            {
              type: "templar.security_team_assignment",
              organizationId: this.#plan.id,
              phase: phase.phase,
              assignments: phase.assignments.map((assignment) => ({
                blockId: assignment.block.id,
                teamId: assignment.teamId,
                memberId: assignment.memberId,
                agentId: assignment.block.agentId,
                roleId: assignment.block.role.id,
                targetCandidateId: assignment.block.targetCandidateId ?? null,
              })),
            },
          ],
        };
      }),
    );
}
