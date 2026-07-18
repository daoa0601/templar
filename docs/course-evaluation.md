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

Before every supervisor turn, Templar appends the exact next-phase identity roster. Supervisors do
not need workspace tools to schedule a phase. The guard still rejects a mismatched roster rather
than silently mapping a model-created alias onto a declared member. For assurance blocks, Templar
also replaces the supervisor-authored task with a deterministic pinned-evidence task: an auditor may
use only its candidate worktree, immutable evidence, evaluator contract/output, Git diff, and trusted
trace. A supervisor cannot make acceptance depend on an unavailable coordinator, specialist, or
other-candidate report.

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

## Separately attested course lab

Templar now has an operator-only path for producing one assignment's passive evidence in Drone. It
does not put a model CLI or model credential in the guest. The Apple provider has no NIC, so Codex,
OpenCode, OpenAI, Z.AI, Vercel AI Gateway, and other remote inference endpoints are intentionally
unreachable there. The model/tool split is explicit:

```text
Codex auth or OpenCode auth on the trusted host
  -> Templar and Agent Blocks orchestration
       -> immutable assignment evidence only

operator approval bound to one signed provider measurement
  -> Drone registered operation
       -> one disposable no-NIC Linux VM
       -> fixed analyzer image and command
       -> specimen + generated context in read-only input disk
       -> assignment evidence + per-job execution statement
```

This preserves the requested model order—GPT-5.6 Sol through the local Codex/ChatGPT session first,
then `zai-coding-plan/glm-5.2` through OpenCode—without copying either authentication store into an
untrusted specimen environment. An agent-in-guest design would need a different signed provider
profile with explicit egress and credential-broker policy; the no-network course approval does not
silently authorize that wider boundary.

The configured Drone operation must be enabled, use `apple_native`, declare `network: none`, and
have exactly this exchange contract:

- required `specimen` input accepting the operator-selected media type;
- required `context` input with
  `application/vnd.templar.course-lab-context+json`;
- required `evidence` output with
  `application/vnd.templar.course-assignment-evidence+json`;
- no other input or output slots.

The image digest, command, environment, user, resources, and output bounds remain in Drone's trusted
operation registry. Templar and its agents cannot supply or override them.

After Drone has been provisioned and its separately held Ed25519 reviewer has signed the exact
driver, kernel, and initfs measurements, read the current ID from `drone doctor`. Repeat that ID in
the submission so an expired or rotated statement cannot be accepted implicitly:

```bash
export TEMPLAR_DRONE_COURSE_LAB_OPERATION_ID=course.assignment.analyze

node --enable-source-maps dist/cli.js course lab submit \
  <manifest-source-artifact-id> \
  /private/extracted-or-original-specimen \
  application/zip \
  --approve-attestation attestation.sha256.<64-hex-digest> \
  --rationale "Analyze this exact assignment specimen in the reviewed no-network VM."

node --enable-source-maps dist/cli.js course lab status lab_<32-hex-digits>

node --enable-source-maps dist/cli.js course lab collect \
  lab_<32-hex-digits> \
  /private/assignment-evidence.json

node --enable-source-maps dist/cli.js course lab snapshot \
  lab_<32-hex-digits> \
  /private/assignment-snapshot.json

node --enable-source-maps dist/cli.js course lab solve \
  lab_<32-hex-digits> \
  --runtime codex \
  --model gpt-5.6-sol

node --enable-source-maps dist/cli.js course lab solve \
  lab_<32-hex-digits> \
  --runtime opencode \
  --model zai-coding-plan/glm-5.2
```

Use the manifest artifact ID that proves the specimen's course scope. Templar records the actual
specimen SHA-256 and size and notes whether it exactly equals that manifest artifact; an extracted
child remains explicitly marked as derived. It never journals the source host path. Approval is
written with mode `0600` before either content-addressed input is staged. Collection succeeds only
for a correlated successful job with a valid per-job execution statement and a complete assignment
evidence object whose questions, checks, observation namespace, and artifact provenance match the
committed corpus manifest.

Each collected file is a one-element assignment-evidence array. Once all five assignments have been
collected, combine the arrays in a private location (for example, `jq -s 'add'`) and pass the result
to `course compose`. Private custody also remains under
`TEMPLAR_HOME/course-lab/<lab-id>`: approval, submission, normalized evidence, the execution
statement, and a collection receipt. None of those files belongs in Git.

`snapshot` revalidates the collected evidence, provider/execution statement, and committed manifest
before producing the model-safe assignment snapshot. Every incident workspace retains
`exercise.json` as the canonical object and adds `observations/index.json`. Normal observations are
materialized as exact raw UTF-8 files whose natural lines are bounded for model CLI readers. Only a
genuinely overlong source line uses ordered JSONL code-point chunks; concatenating `text` fields by
`chunk_index` reconstructs the canonical value. The index records the encoding, size, maximum line,
and SHA-256 digest, so runtime display limits cannot silently hide the end of a disassembly string.

The one-assignment organization is five phases and six worker turns: one purple evidence
coordinator, one passive red specialist, two independent blue solvers, two pinned assurance
auditors, then deterministic selection. It permits two concurrent workers, ten minutes per model
turn, one hour wall clock, and 700,000 charged tokens. These larger time limits accommodate both the
Codex and OpenCode adapters without changing the six-member roster, phase count, concurrency, token
cap, evaluator, mutation allowlist, or sandbox.

### Recorded local smoke validation

The following 2026-07-18 runs validate the integration; they are one-machine smoke results, not a
model benchmark or course grade. Private journals retain the raw events and outputs.

| Boundary                               | Result                 | Elapsed | Charged tokens | Selection gates                                                  |
| -------------------------------------- | ---------------------- | ------: | -------------: | ---------------------------------------------------------------- |
| Apple lightweight VM evidence job      | succeeded              |  1.57 s |            n/a | no NIC, fixed operation, signed measurement, execution statement |
| GPT-5.6 Sol through Codex/ChatGPT auth | accepted `candidate_a` |  8m 16s |        509,100 | evaluator 100, complete trace, audit pass                        |
| GLM-5.2 through Z.AI/OpenCode auth     | accepted `candidate_a` | 20m 35s |        111,945 | evaluator 100, complete trace, audit pass                        |

The local VM row used an operator smoke-signing key kept outside Drone state. It validates the
measurement/admission/execution chain but does not demonstrate organizational reviewer
independence; a production attestation still requires a genuinely separate reviewer and key owner.

Intermediate fail-closed trials were also retained: an undeclared GLM member alias was rejected,
the initial 15-minute global allowance expired before audits, and an overly fragmented evidence
mirror caused 300-second worker timeouts. Those failures led to the exact-roster prompt binding,
provider-neutral time bounds, and raw-text-first evidence mirror above. No failed trial applied a
candidate.

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
