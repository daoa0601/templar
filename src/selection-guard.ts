import type {
  AgentRuntime,
  RuntimeTurnInput,
  RuntimeTurnResult,
  SupervisorDecision,
} from "@agentic-orch/agent-blocks/templates/scoped-worktree";
import { Effect } from "effect";

interface EvaluationOutput {
  readonly passed: boolean;
  readonly score: number;
}

interface CandidatePromptSnapshot {
  readonly candidateId?: unknown;
  readonly evaluation?: {
    readonly passed?: unknown;
    readonly stdoutTail?: unknown;
  };
}

interface ObservationPromptRecord {
  readonly roleId?: unknown;
  readonly targetCandidateId?: unknown;
  readonly report?: unknown;
}

export interface DeterministicSelection {
  readonly ready: boolean;
  readonly selectedCandidateId?: string;
  readonly reason: string;
  readonly scores: ReadonlyArray<{
    readonly candidateId: string;
    readonly score: number;
  }>;
}

export interface DeterministicSelectionOptions {
  readonly requirePinnedAuditors?: boolean;
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function jsonSection(prompt: string, startLabel: string, endLabel: string): unknown {
  const label = prompt.indexOf(startLabel);
  if (label < 0) return undefined;
  const start = label + startLabel.length;
  const end = prompt.indexOf(endLabel, start);
  if (end < 0) return undefined;
  try {
    return JSON.parse(prompt.slice(start, end).trim()) as unknown;
  } catch {
    return undefined;
  }
}

function evaluationOutput(value: unknown): EvaluationOutput | undefined {
  if (typeof value !== "string") return undefined;
  const lines = value.trim().split("\n").reverse();
  for (const line of lines) {
    try {
      const parsed = record(JSON.parse(line));
      if (
        parsed?.passed === true &&
        typeof parsed.score === "number" &&
        Number.isFinite(parsed.score) &&
        parsed.score >= 0 &&
        parsed.score <= 100
      ) {
        return { passed: true, score: parsed.score };
      }
    } catch {
      // Evaluator output is one JSON record; ignore unrelated bounded prefix lines.
    }
  }
  return undefined;
}

function candidateOrdinal(candidateId: string): number {
  if (candidateId === "candidate_a") return 0;
  if (candidateId === "candidate_b") return 1;
  return Number.MAX_SAFE_INTEGER;
}

function hasPinnedAuditor(
  observations: ReadonlyArray<ObservationPromptRecord>,
  candidateId: string,
): boolean {
  return observations.some((observation) => {
    const report = record(observation.report);
    return (
      observation.roleId === "evaluation_auditor" &&
      observation.targetCandidateId === candidateId &&
      report?.status === "completed" &&
      Array.isArray(report.evidence)
    );
  });
}

/**
 * Replays only trusted harness prompt projections: independent evaluator results and pinned review
 * observations. Model prose never contributes to the score or tie-break.
 */
export function deterministicSelectionFromSupervisorPrompt(
  prompt: string,
  options: DeterministicSelectionOptions = {},
): DeterministicSelection {
  const requirePinnedAuditors = options.requirePinnedAuditors ?? true;
  const rawCandidates = jsonSection(
    prompt,
    "Current candidate snapshots. Full patches are durable artifacts; reviewers can inspect a chosen\ncandidate directly when assigned with targetCandidateId:\n",
    "\n\nHarness rules you cannot override:",
  );
  const rawObservations = jsonSection(
    prompt,
    "Fresh observations from the previous worker batch:\n",
    "\n\nCurrent candidate snapshots.",
  );
  if (!Array.isArray(rawCandidates) || !Array.isArray(rawObservations)) {
    return { ready: false, reason: "trusted_harness_projection_missing", scores: [] };
  }
  const candidates = rawCandidates as ReadonlyArray<CandidatePromptSnapshot>;
  const observations = rawObservations as ReadonlyArray<ObservationPromptRecord>;
  if (candidates.length !== 2) {
    return { ready: false, reason: "exactly_two_candidate_snapshots_required", scores: [] };
  }

  const scores: Array<{ readonly candidateId: string; readonly score: number }> = [];
  for (const candidate of candidates) {
    if (typeof candidate.candidateId !== "string") {
      return { ready: false, reason: "candidate_id_missing", scores: [] };
    }
    const output = evaluationOutput(candidate.evaluation?.stdoutTail);
    if (candidate.evaluation?.passed === true && output?.passed === true) {
      scores.push({ candidateId: candidate.candidateId, score: output.score });
    }
    if (requirePinnedAuditors && !hasPinnedAuditor(observations, candidate.candidateId)) {
      return {
        ready: false,
        reason: `pinned_evaluation_auditor_missing:${candidate.candidateId}`,
        scores,
      };
    }
  }
  scores.sort(
    (left, right) =>
      right.score - left.score ||
      candidateOrdinal(left.candidateId) - candidateOrdinal(right.candidateId) ||
      left.candidateId.localeCompare(right.candidateId),
  );
  const selected = scores[0];
  if (selected === undefined) {
    return { ready: true, reason: "no_evaluator_passing_candidate", scores };
  }
  return {
    ready: true,
    selectedCandidateId: selected.candidateId,
    reason: "highest_deterministic_score_then_candidate_ordinal",
    scores,
  };
}

function guardedSupervisorResult(
  input: RuntimeTurnInput,
  output: RuntimeTurnResult,
  options: DeterministicSelectionOptions,
): RuntimeTurnResult {
  if (input.agentId !== "supervisor") return output;
  let decision: SupervisorDecision;
  try {
    decision = JSON.parse(output.finalText) as SupervisorDecision;
  } catch {
    return output;
  }
  if (decision.status !== "accept") return output;

  const selection = deterministicSelectionFromSupervisorPrompt(input.prompt, options);
  const guarded: SupervisorDecision =
    !selection.ready || selection.selectedCandidateId === undefined
      ? {
          status: "stop",
          summary: `Templar selection guard stopped acceptance: ${selection.reason}.`,
          assignments: [],
          selectedCandidateId: null,
        }
      : {
          status: "accept",
          summary: `Templar mechanically selected ${selection.selectedCandidateId}: ${selection.reason}.`,
          assignments: [],
          selectedCandidateId: selection.selectedCandidateId,
        };
  return {
    ...output,
    finalText: JSON.stringify(guarded),
    events: [
      ...output.events,
      {
        type: "templar.selection_guard",
        requestedCandidateId: decision.selectedCandidateId,
        selectedCandidateId: guarded.selectedCandidateId,
        reason: selection.reason,
        scores: selection.scores,
      },
    ],
  };
}

export class DeterministicSelectionRuntime implements AgentRuntime {
  readonly #delegate: AgentRuntime;
  readonly #options: DeterministicSelectionOptions;

  constructor(delegate: AgentRuntime, options: DeterministicSelectionOptions = {}) {
    this.#delegate = delegate;
    this.#options = options;
  }

  readonly runTurn = (input: RuntimeTurnInput) =>
    this.#delegate
      .runTurn(input)
      .pipe(Effect.map((output) => guardedSupervisorResult(input, output, this.#options)));
}
