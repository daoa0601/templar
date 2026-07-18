# Whole-course security evaluation

Templar can turn the locally held course corpus into one versioned, evidence-bounded evaluation of
an agent organization. The committed manifest describes five assignments and 33 required outputs:
Windows DFIR, static x86 analysis, dynamic x86 analysis, managed .NET analysis, and the Darkwood
batch-analysis exercise. Course PDFs, archives, executable specimens, answers, personal identifiers,
and sealed grading data are not committed.

This workflow tests orchestration and evidence-grounded analysis. It is not a claim that an
application-level agent sandbox safely contains malware.

## Build the private snapshot

Use a trusted local course-material checkout and an operator-produced evidence bundle. Inventory
validates the manifest's expected files and content identities. Compose emits a strict snapshot
containing requirement text, bounded passive observations, and analyzer provenance, but no specimen
bytes or host paths. Long line-oriented observations are segmented into stable citable records so a
runtime's per-line read limit cannot silently hide later table rows.

```bash
pnpm build

node --enable-source-maps dist/cli.js course inventory /path/to/course-material

node --enable-source-maps dist/cli.js course compose \
  /path/to/course-material \
  /private/assignment-evidence.json \
  /private/course-snapshot.json
```

The personalized checksum question remains parameterized by the operator's student ID. Templar
does not guess or commit that identifier. Create private outputs with restrictive permissions and
keep them outside the repository; `TEMPLAR_HOME` and `.templar/` are ignored but may still contain
course answers and sensitive traces.

## Run the organization

The five bounded phases are fixed:

1. A purple-team coordinator maps all 33 requirements to evidence, checks, gaps, and timeline
   caveats without supplying final answers.
2. Four scoped specialists run as one phase: Windows intrusion, native reverse engineering,
   managed reverse engineering, and batch analysis.
3. Two blue-team solvers independently re-read the immutable evidence, falsify leads, and each
   writes `result.json` plus `report.md` in a separate Git worktree.
4. Two assurance agents are pinned one-to-one to the immutable candidate snapshots. Each reruns the
   deterministic evaluator and audits evidence alignment and trace integrity without selecting.
5. The supervisor may accept only the highest-scoring evaluator-passing candidate whose pinned
   audit passes. Exact score ties use candidate ordinal; otherwise the run stops without applying.

The fail-closed phase guard owns literal `agentId`, `roleId`, and `targetCandidateId` tuples. A model
cannot rename a member, skip a phase, dispatch a new member, add turns, broaden a workspace, or
select a failing candidate. The course budget is nine worker turns, four concurrent workers, ten
minutes per model turn, one hour wall clock, and 1.5 million charged tokens.

### Codex with ChatGPT authentication

```bash
codex login
codex login status

TEMPLAR_HOME=/private/templar-codex \
node --enable-source-maps dist/cli.js course solve /private/course-snapshot.json \
  --runtime codex \
  --model gpt-5.6-sol
```

The Codex adapter invokes the local CLI with isolated user configuration and its normal
ChatGPT-authenticated session. Templar and Agent Blocks do not read, copy, or journal the
credential. The explicit model ID is operator configuration; an HTTP caller cannot choose it.

### GLM through OpenCode

Authenticate the trusted local OpenCode installation with the Z.AI Coding Plan first, then run:

```bash
TEMPLAR_HOME=/private/templar-glm \
TEMPLAR_OPENCODE_BINARY=/trusted/path/to/opencode \
node --enable-source-maps dist/cli.js course solve /private/course-snapshot.json \
  --runtime opencode \
  --model zai-coding-plan/glm-5.2
```

The OpenCode adapter uses the provider authentication already owned by OpenCode; it does not read
or copy the credential. Prompts travel over stdin. Each invocation uses isolated configuration,
disables sharing, updates, plugins, model discovery, web access, subagents, skills, LSP, questions,
and external-directory access, and applies a deny-by-default permission map. Within a candidate
worktree the model may read/search and edit, inspect Git status/diff, and run only the pinned local
evaluator command; the course contract and deterministic evaluator accept changes to only the two
declared outputs. An empty-output OpenCode startup database-lock collision may be retried twice and
is retained as a raw adapter event; partially generated turns are never retried.

The OpenCode permission layer is an application policy, not an OS, container, or VM boundary. This
course tier is safe by construction only because agents receive hashed passive observations rather
than executable specimens. Any future direct debugging, sample execution, unpacking, or dynamic
network behavior must be a separately registered and approved Drone operation in a disposable VM
with its own network, resource, rollback, and audit controls.

## Deterministic demo and sealed grading

The scripted demo checks the complete orchestration and evaluator contracts without model or
provider usage:

```bash
TEMPLAR_HOME=/private/templar-demo \
node --enable-source-maps dist/cli.js course demo /private/course-snapshot.json
```

After a real run, grade a preserved candidate result with an operator-owned sealed rubric:

```bash
node --enable-source-maps dist/cli.js course grade \
  /private/result.json \
  /private/sealed-rubric.json
```

The rubric never enters an agent worktree or prompt. The in-worktree evaluator checks schema,
complete 33-requirement coverage, assignment-scoped citations, known observation IDs, provenance,
and required report sections. The sealed grader judges semantic answers afterward. Keep these two
meanings distinct:

- `evidence_checks_relied_on` records trusted upstream analyzer provenance for cited observations.
- `checks_performed` records only candidate actions visible in its trace, such as running the local
  deterministic evaluator.

Real-provider runs are deliberately opt-in and are not CI tests. Private journals preserve raw
runtime events, session identifiers, evaluator output, patches, and token accounting; the public
control-plane projection removes those fields.
