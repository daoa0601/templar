import { Schema, SchemaParser } from "effect";

import type { CourseCorpusManifest } from "./course-corpus.js";
import { invalidInput } from "./errors.js";

const CriterionSchema = Schema.Struct({
  criterion_id: Schema.String,
  target: Schema.Literals(["answer", "uncertainty", "observation_ids"]),
  any_of: Schema.Array(Schema.String),
});

const RequirementRubricSchema = Schema.Struct({
  requirement_id: Schema.String,
  criteria: Schema.Array(CriterionSchema),
  minimum_criteria: Schema.Number,
});

const CourseRubricSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  corpus_id: Schema.String,
  requirements: Schema.Array(RequirementRubricSchema),
});

const CandidateResultSchema = Schema.Struct({
  schema_version: Schema.Literal("1"),
  status: Schema.String,
  summary: Schema.String,
  answers: Schema.Array(
    Schema.Struct({
      question_id: Schema.String,
      answer: Schema.String,
      observation_ids: Schema.Array(Schema.String),
      uncertainty: Schema.String,
    }),
  ),
  unanswered_question_ids: Schema.Array(Schema.String),
  evidence_checks_relied_on: Schema.Array(Schema.String),
  checks_performed: Schema.Array(Schema.String),
  external_mutations: Schema.Array(Schema.Unknown),
});

const decodeRubricShape = SchemaParser.decodeUnknownSync(CourseRubricSchema, {
  errors: "all",
  onExcessProperty: "error",
});
const decodeCandidateShape = SchemaParser.decodeUnknownSync(CandidateResultSchema, {
  errors: "all",
  onExcessProperty: "error",
});

const SAFE_ID = /^[a-z][a-z0-9_.-]{0,127}$/u;

export type CourseRubricTarget = "answer" | "uncertainty" | "observation_ids";

export interface CourseRubricCriterion {
  readonly criterion_id: string;
  readonly target: CourseRubricTarget;
  readonly any_of: ReadonlyArray<string>;
}

export interface CourseRequirementRubric {
  readonly requirement_id: string;
  readonly criteria: ReadonlyArray<CourseRubricCriterion>;
  readonly minimum_criteria: number;
}

export interface CourseRubric {
  readonly schema_version: "1";
  readonly corpus_id: string;
  readonly requirements: ReadonlyArray<CourseRequirementRubric>;
}

export interface CourseRequirementGrade {
  readonly requirement_id: string;
  readonly passed: boolean;
  readonly criteria_passed: number;
  readonly criteria_required: number;
  readonly criteria_total: number;
  readonly failed_criterion_ids: ReadonlyArray<string>;
}

export interface CourseGrade {
  readonly schema_version: "1";
  readonly grader_version: "templar-course-sealed-v1";
  readonly corpus_id: string;
  readonly passed: boolean;
  readonly requirements_passed: number;
  readonly requirements_total: number;
  readonly criteria_passed: number;
  readonly criteria_total: number;
  readonly requirements: ReadonlyArray<CourseRequirementGrade>;
}

function bounded(value: string, label: string, maximum: number): string {
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > maximum ||
    normalized.includes(String.fromCharCode(0))
  ) {
    throw invalidInput(`${label} is invalid.`);
  }
  return normalized;
}

function id(value: string, label: string): string {
  const normalized = bounded(value, label, 128);
  if (!SAFE_ID.test(normalized)) throw invalidInput(`${label} is invalid.`);
  return normalized;
}

function unique(values: ReadonlyArray<string>, label: string): void {
  if (new Set(values).size !== values.length) throw invalidInput(`${label} contains duplicates.`);
}

function sameMembers(left: ReadonlyArray<string>, right: ReadonlyArray<string>): boolean {
  const expected = [...right].sort();
  return (
    left.length === expected.length &&
    [...left].sort().every((value, index) => value === expected[index])
  );
}

function searchable(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US").replace(/\s+/gu, " ").trim();
}

export function decodeCourseRubric(value: unknown, manifest: CourseCorpusManifest): CourseRubric {
  let input: typeof CourseRubricSchema.Type;
  try {
    input = decodeRubricShape(value);
  } catch (cause) {
    throw invalidInput("The sealed course rubric does not match its strict schema.", cause);
  }
  if (input.corpus_id !== manifest.corpus_id) {
    throw invalidInput("The sealed rubric targets a different corpus.");
  }
  const expectedRequirements = manifest.assignments.flatMap(
    (assignment) => assignment.requirement_ids,
  );
  const requirements = input.requirements.map((requirement, requirementIndex) => {
    const requirementId = id(
      requirement.requirement_id,
      `requirements[${requirementIndex}].requirement_id`,
    );
    if (requirement.criteria.length === 0 || requirement.criteria.length > 64) {
      throw invalidInput(`Rubric ${requirementId} must contain 1-64 criteria.`);
    }
    if (
      !Number.isSafeInteger(requirement.minimum_criteria) ||
      requirement.minimum_criteria <= 0 ||
      requirement.minimum_criteria > requirement.criteria.length
    ) {
      throw invalidInput(`Rubric ${requirementId} has an invalid minimum_criteria.`);
    }
    const criteria = requirement.criteria.map((criterion, criterionIndex) => {
      const criterionId = id(
        criterion.criterion_id,
        `${requirementId}.criteria[${criterionIndex}].criterion_id`,
      );
      if (criterion.any_of.length === 0 || criterion.any_of.length > 32) {
        throw invalidInput(`Rubric criterion ${criterionId} must contain 1-32 alternatives.`);
      }
      const alternatives = criterion.any_of.map((alternative, alternativeIndex) =>
        bounded(alternative, `${criterionId}.any_of[${alternativeIndex}]`, 256),
      );
      unique(alternatives.map(searchable), `Rubric criterion ${criterionId} alternatives`);
      return {
        criterion_id: criterionId,
        target: criterion.target,
        any_of: alternatives,
      } satisfies CourseRubricCriterion;
    });
    unique(
      criteria.map((criterion) => criterion.criterion_id),
      `Rubric ${requirementId} criterion IDs`,
    );
    return {
      requirement_id: requirementId,
      criteria,
      minimum_criteria: requirement.minimum_criteria,
    } satisfies CourseRequirementRubric;
  });
  unique(
    requirements.map((requirement) => requirement.requirement_id),
    "Rubric requirement IDs",
  );
  if (
    !sameMembers(
      requirements.map(({ requirement_id }) => requirement_id),
      expectedRequirements,
    )
  ) {
    throw invalidInput("The sealed rubric must cover every corpus requirement exactly once.");
  }
  return {
    schema_version: "1",
    corpus_id: input.corpus_id,
    requirements,
  };
}

/**
 * Apply a local rubric after orchestration. Only criterion IDs and pass/fail counts are returned;
 * the answer terms remain in the operator-controlled rubric and never enter agent worktrees.
 */
export function gradeCourseCandidate(options: {
  readonly candidate: unknown;
  readonly rubric: unknown;
  readonly manifest: CourseCorpusManifest;
}): CourseGrade {
  const rubric = decodeCourseRubric(options.rubric, options.manifest);
  let candidate: typeof CandidateResultSchema.Type;
  try {
    candidate = decodeCandidateShape(options.candidate);
  } catch (cause) {
    throw invalidInput("The course candidate does not match its strict result schema.", cause);
  }
  if (
    candidate.status !== "completed" ||
    candidate.unanswered_question_ids.length !== 0 ||
    candidate.external_mutations.length !== 0
  ) {
    throw invalidInput("Only a completed, non-mutating course candidate can be graded.");
  }
  unique(
    candidate.answers.map((answer) => answer.question_id),
    "Candidate answer question IDs",
  );
  if (
    !sameMembers(
      candidate.answers.map((answer) => answer.question_id),
      rubric.requirements.map((requirement) => requirement.requirement_id),
    )
  ) {
    throw invalidInput("The candidate must answer every rubric requirement exactly once.");
  }

  const requirements = rubric.requirements.map((requirement) => {
    const answer = candidate.answers.find(
      (candidateAnswer) => candidateAnswer.question_id === requirement.requirement_id,
    )!;
    const targets: Readonly<Record<CourseRubricTarget, string>> = {
      answer: searchable(answer.answer),
      uncertainty: searchable(answer.uncertainty),
      observation_ids: searchable(answer.observation_ids.join(" ")),
    };
    const failedCriterionIds: string[] = [];
    for (const criterion of requirement.criteria) {
      const haystack = targets[criterion.target];
      if (!criterion.any_of.some((alternative) => haystack.includes(searchable(alternative)))) {
        failedCriterionIds.push(criterion.criterion_id);
      }
    }
    const criteriaPassed = requirement.criteria.length - failedCriterionIds.length;
    return {
      requirement_id: requirement.requirement_id,
      passed: criteriaPassed >= requirement.minimum_criteria,
      criteria_passed: criteriaPassed,
      criteria_required: requirement.minimum_criteria,
      criteria_total: requirement.criteria.length,
      failed_criterion_ids: failedCriterionIds,
    } satisfies CourseRequirementGrade;
  });
  const criteriaTotal = requirements.reduce(
    (sum, requirement) => sum + requirement.criteria_total,
    0,
  );
  const criteriaPassed = requirements.reduce(
    (sum, requirement) => sum + requirement.criteria_passed,
    0,
  );
  return {
    schema_version: "1",
    grader_version: "templar-course-sealed-v1",
    corpus_id: rubric.corpus_id,
    passed: requirements.every((requirement) => requirement.passed),
    requirements_passed: requirements.filter((requirement) => requirement.passed).length,
    requirements_total: requirements.length,
    criteria_passed: criteriaPassed,
    criteria_total: criteriaTotal,
    requirements,
  };
}
