# Templar

Templar is a local, policy-gated network and security analysis application built on the sibling
`@agentic-orch/agent-blocks` package. It ships five workflows: `telecom_incident` for bounded packet-loss
diagnosis, `pcap_security_triage` for passive analysis of a locally staged classic PCAP,
`exercise_solve` for bounded reverse-engineering exercises, `source_security_audit` for
attacker-oriented static source review, and `source_security_fix` for isolated patch and regression
test candidates derived from an accepted audit. All five use explicit Agent Blocks roles, isolated candidate
worktrees, a local evaluator, and mechanical candidate selection.

Templar is a single-user local system, not a production or multi-tenant security boundary.

## Architecture

```text
browser or CLI
  -> Templar loopback HTTP application
       -> strict workflow-specific decoder
       -> content-addressed PCAP/exercise/source stores and bounded analyzers
       -> dedicated committed incident Git repository
       -> @agentic-orch/agent-blocks
            -> read-only evidence researcher
            -> candidate_a and candidate_b in isolated writable worktrees
            -> trusted deterministic evaluator for each snapshot
            -> optional candidate-pinned reviewers (telecom, source audit, and source fix)
            -> deterministic score/ordinal selection guard
            -> selected patch applied only to the incident repository
       -> persisted harness run/event projections
```

The harness owns role scope, worktree isolation, lifecycle, budgets, concurrency, cancellation,
evaluation snapshots, durable events, and patch application. Templar does not recreate an agent loop.
The dashboard is a thin client of the Templar API and is never authoritative run state.

The default runtime is the locally installed Codex CLI authenticated through ChatGPT. Templar does
not need or read an OpenAI API key:

```bash
codex login
codex login status
```

## Requirements and setup

- Node.js 22.22.2+, 24.15.0+, or 26+
- Git
- pnpm 11.13.1
- A built sibling checkout at `../agent-blocks` for the current frozen install
- Sibling checkouts at `../drone-client`, `../node-guardrails`, and `../ts-quality` for the current
  frozen install
- A locally authenticated `codex` CLI for real agent runs

```bash
cd templar
pnpm install --frozen-lockfile
pnpm check
pnpm build
```

The package manifest uses explicit local workspace dependencies:

```json
{
  "dependencies": {
    "@agentic-orch/agent-blocks": "workspace:*",
    "@agentic-orch/drone-client": "workspace:*",
    "@agentic-orch/node-guardrails": "workspace:*"
  },
  "devDependencies": {
    "@agentic-orch/ts-quality": "workspace:*"
  }
}
```

Templar consumes the public Drone v1 contracts and bounded HTTP client from
`@agentic-orch/drone-client`, plus neutral bounded HTTP and content-addressed storage primitives from
`@agentic-orch/node-guardrails/http` and `/cas`. The lock resolves all four modules as sibling
`link:` entries, so every frozen install requires the four directories listed above and cannot
silently download similarly named registry packages. Templar retains PCAP/source/exercise
validation, authorization, workflow semantics, and application error mapping.

Effect is pinned to `4.0.0-beta.98`. Upgrade it intentionally and rerun the complete checks.

## Running Templar

Copy or export the development defaults from `.env.example`, then run:

```bash
pnpm dev
```

Open `http://127.0.0.1:8080/`. With the default loopback binding and no token, Templar logs that it is
in development-only loopback mode. A bearer token is mandatory for any non-loopback bind.

Supported CLI commands are:

```bash
# Start the HTTP server and dashboard.
pnpm dev

# Complete deterministic fake-runtime demo; no model, network, or subscription usage.
pnpm demo

# One bounded real run through the locally authenticated Codex CLI.
# This consumes subscription usage and is intentionally not part of tests.
pnpm sample

# Analyze two small CTU-13 security captures without invoking a model.
pnpm smoke:ctu13

# Run DonBot through the complete three-round harness with the scripted runtime.
pnpm smoke:ctu13:harness

# Build the static course snapshot and exercise the complete three-round workflow locally.
# The executable is streamed from its archive into objdump and is never placed in an agent workspace.
pnpm smoke:course-static

# Run the same exercise with real agents through the authenticated Codex CLI.
# This consumes ChatGPT subscription usage.
pnpm smoke:course-static:real

# Run the compiled server.
pnpm build
pnpm start
```

Smoke state stays under the ignored `.templar/smoke` directory. The CTU-13 harness command and the
default course command use the scripted runtime. The `:real` course command is the opt-in path that
invokes Codex.

Configuration:

| Variable                                       |                 Default | Meaning                                                      |
| ---------------------------------------------- | ----------------------: | ------------------------------------------------------------ |
| `TEMPLAR_HOST`                                 |             `127.0.0.1` | HTTP bind host. Non-loopback requires a token.               |
| `TEMPLAR_PORT`                                 |                  `8080` | HTTP port.                                                   |
| `TEMPLAR_HOME`                                 |            `~/.templar` | Incident, artifact, acknowledgment, and harness state root.  |
| `TEMPLAR_BEARER_TOKEN`                         |                   unset | Optional in loopback development; required otherwise.        |
| `TEMPLAR_MAX_ACTIVE_RUNS`                      |                     `2` | Process-local active-run admission cap.                      |
| `TEMPLAR_MAX_JSON_BYTES`                       |                 `65536` | JSON request-body cap.                                       |
| `TEMPLAR_MAX_PCAP_BYTES`                       |               `8388608` | PCAP upload and analysis byte cap.                           |
| `TEMPLAR_MAX_PCAP_PACKETS`                     |                 `50000` | Packet parsing cap.                                          |
| `TEMPLAR_MAX_EXERCISE_SNAPSHOT_BYTES`          |                `524288` | Decoded exercise snapshot cap.                               |
| `TEMPLAR_MAX_SOURCE_SNAPSHOT_BYTES`            |               `8388608` | Canonical source snapshot cap.                               |
| `TEMPLAR_DRONE_ENABLED`                        |                  `true` | Enables sandbox capability discovery through Drone.          |
| `TEMPLAR_DRONE_URL`                            | `http://127.0.0.1:8090` | Drone service endpoint; plain HTTP is accepted only locally. |
| `TEMPLAR_DRONE_TOKEN`                          |                   unset | Optional bearer token for Drone.                             |
| `TEMPLAR_DRONE_TIMEOUT_MS`                     |                  `1000` | Bound for Drone control-plane requests.                      |
| `TEMPLAR_DRONE_SOURCE_VALIDATION_OPERATION_ID` |                   unset | Registered operation used for accepted-fix replay.           |

Callers cannot choose a workspace, evaluator command, Codex setting, executable, budget, URL, or host
path through incident input.

## Workflow and artifact API

`IncidentInput v1` is strict: unknown fields are rejected.

```json
{
  "schema_version": "1",
  "request": "Investigate reported packet loss using only supplied evidence.",
  "observations": [
    {
      "observation_id": "loss-rate",
      "kind": "operator_metric",
      "value": 2.5,
      "unit": "percent"
    }
  ],
  "ticket_ref": "NET-42",
  "reported_priority": "P2",
  "pcap_artifact_id": "pcap_sha256_<64 lowercase hex characters>"
}
```

`ticket_ref` is validated Jira-like untrusted metadata only. Release one performs no Jira request.
PCAPs must first be uploaded as a capped binary body. Templar accepts classic PCAP magic/version and
Ethernet link type, explicitly rejects pcapng, hashes the bytes, writes an opaque content-addressed
artifact atomically, and rejects symlinks. Resolution returns the exact bounded bytes verified from
one open content-store file handle; PCAP, exercise, and source consumers use those verified byte
snapshots and never reopen a returned store pathname. There is no URL download, caller filename, or
local-path API.

Security triage has a smaller fixed-purpose input. The route selects the workflow; callers cannot
submit a prompt or workflow ID in the body:

```json
{
  "schema_version": "1",
  "pcap_artifact_id": "pcap_sha256_<64 lowercase hex characters>"
}
```

Exercise solving also uses a fixed-purpose input. First stage a strict `ExerciseSnapshot v1`, then
submit only its content-addressed ID:

```json
{
  "schema_version": "1",
  "exercise_snapshot_id": "exercise_sha256_<64 lowercase hex characters>"
}
```

An exercise snapshot contains bounded question text, artifact identity, analyzer identity, static
observations, and declared checks. It has no executable, host-path lookup, URL-fetch, arbitrary agent
prompt, or evaluator-command field. Path- or URL-like strings inside analyzer output remain untrusted
evidence and do not cause Templar to access them.

Source audit accepts a strict text-only snapshot, then runs only from its opaque artifact ID:

```json
{
  "schema_version": "1",
  "repository": { "name": "sample-service", "revision": "0123456789abcdef" },
  "files": [{ "path": "src/server.ts", "content": "export function handler() {}\n" }]
}
```

```json
{
  "schema_version": "1",
  "source_snapshot_id": "source_sha256_<64 lowercase hex characters>"
}
```

Paths must be portable relative paths and cannot contain traversal, `.git`, case collisions, or
file/directory collisions. Templar never accepts a repository URL, archive, symlink, caller-selected
workspace, or host path. Its lexical entry-point/input/sink index is an inventory of review leads,
not a vulnerability scanner verdict.

A source fix can reference only the run ID of an accepted, evaluation-passing source audit. Its
findings, snapshot, scope, and promotion impact are derived from that result:

```json
{
  "schema_version": "1",
  "audit_run_id": "<accepted source_security_audit run ID>"
}
```

Candidates may edit only their isolated `target/` tree, must link every change and regression test
to an accepted finding, and must report dynamic validation as `not_run`. Templar never writes a fix
back to the caller's repository.

Routes:

| Method and path                                  | Purpose                                                  |
| ------------------------------------------------ | -------------------------------------------------------- |
| `GET /`                                          | Static Templar dashboard.                                |
| `GET /health/live`                               | Process liveness.                                        |
| `GET /health/ready`                              | Local storage readiness.                                 |
| `GET /api/workflows`                             | Typed workflow catalog and release states.               |
| `GET /api/labs`                                  | Read-only sandbox-provider capability status.            |
| `POST /api/artifacts/pcap`                       | Stage one classic PCAP binary.                           |
| `POST /api/artifacts/exercise-snapshot`          | Stage one strict exercise snapshot.                      |
| `POST /api/artifacts/source-snapshot`            | Stage one strict text-only source snapshot.              |
| `POST /api/incidents`                            | Compatibility alias for a telecom incident run.          |
| `POST /api/workflows/telecom_incident/runs`      | Start a strictly decoded telecom incident run.           |
| `POST /api/workflows/pcap_security_triage/runs`  | Start passive security triage of one staged PCAP.        |
| `POST /api/workflows/exercise_solve/runs`        | Solve one staged static-analysis exercise.               |
| `POST /api/workflows/source_security_audit/runs` | Audit one staged source snapshot.                        |
| `POST /api/workflows/source_security_fix/runs`   | Create isolated fixes for one accepted source audit.     |
| `GET /api/runs`                                  | Newest-first persisted run list.                         |
| `GET /api/runs/:runId`                           | Persisted run projection and budget usage.               |
| `GET /api/runs/:runId/events?after=N`            | Cursor-based redacted event timeline.                    |
| `GET /api/runs/:runId/result`                    | Accepted output, evaluator result, and promotion status. |
| `POST /api/runs/:runId/cancel`                   | Interrupt a fiber owned by this process.                 |
| `POST /api/runs/:runId/acknowledge`              | Persist an immutable human promotion acknowledgment.     |
| `POST /api/runs/:runId/verify`                   | Submit an acknowledged source fix to Drone.              |
| `GET /api/runs/:runId/verification`              | Read the correlated Drone validation job.                |

When configured, send `Authorization: Bearer <TEMPLAR_BEARER_TOKEN>` to every `/api/*` route. In
tokenless loopback mode, ordinary local CLI calls and same-origin dashboard calls remain available;
Templar rejects non-loopback `Host` authorities, opaque or mismatched browser origins, and
cross-origin `Sec-Fetch-Site` indicators. This also prevents an attacker-controlled DNS name from
satisfying the boundary merely because it resolves to loopback. Health and static assets remain
available without authentication. Errors use stable redacted JSON codes.

Every mutation endpoint that accepts JSON—including snapshot staging, workflow submission,
promotion acknowledgment, and Drone verification—requires `application/json`, rejects encoded
bodies, and caps the bytes read before parsing. PCAP staging is the separate bounded binary-body
route. Rejected body reads close keep-alive and receive only a bounded cleanup interval.

## Evidence, findings, and hypotheses

Templar keeps three data classes separate:

- `EvidenceItem` records an immutable source identity, SHA-256, acquisition availability, context,
  sensitivity, parser version, source metadata, and typed facts.
- `Finding` is a reproducible rule result referencing evidence IDs, fact IDs, and exact
  document/section citations.
- `Hypothesis` is an interpretation referencing findings, with confidence, alternatives, and
  unresolved evidence needs.

Rendered prose never becomes evidence. A ticket reference that was not retrieved remains an explicit
gap. Packet parser failures and unavailable checks likewise cannot become a clean verdict.

Security triage uses the same separation more directly: candidates reference bounded packet
observations, form low/moderate-confidence hypotheses with alternatives and unknowns, then choose
only fixed passive defensive actions. Packet summaries cannot claim confirmed compromise, execution,
malware family, exfiltration, or actor attribution.

The classic-PCAP analyzer has stable facts for capture metadata, protocol counts, IPv4 talkers and
conversations, destination services, port-aware transport conversations, source fan-out and TCP
signals, TCP RST/zero-window events, payload/SYN/FIN sequence retransmissions, and DNS query versus
response counts using the QR flag. Repeated pure ACKs consume no sequence space and are not
retransmissions. Non-initial IPv4 fragments are not parsed as transport headers. DNS over TCP honors
its two-byte message-length prefix.

The versioned `POLICY-TCP-RETRANS-001` cites `SOP-NET-001#1`. Exactly 3% and 7% are
`boundary_ambiguous` and require review because the source prose overlaps at those boundaries.

## Workflow and capability catalog

Every catalog record declares schemas, required capability, authorization checkpoint, network and
filesystem modes, tool allowlist, finite budgets, evaluator/trace-auditor requirements, persistence,
data sensitivity, and release state.

| Capability         | Boundary                                                                                                                                                                                              |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PASSIVE_READ`     | Supplied evidence, offline parsing/correlation, and reports. No upload to third parties, execution, credentials, scanning, exploitation, or endpoint changes.                                         |
| `DEFENSIVE_ADVICE` | Reversible containment recommendations only; it never implies a defensive change.                                                                                                                     |
| `RE_STATIC`        | No-execution, egress-denied, resource-bounded static parsing.                                                                                                                                         |
| `RE_DYNAMIC_LAB`   | Requires an attested disposable lab, simulated/allowlisted network, quarantine, timeout, rollback, logging, emergency stop, and human approval.                                                       |
| `ACTIVE_TEST`      | Disabled by default; requires verified current written ROE, exact target/method allowlists, exclusions, legal grantor, emergency contact, kill switch, lab attestation, and immediate human approval. |

`telecom_incident`, `pcap_security_triage`, `exercise_solve`, `source_security_audit`, and
`source_security_fix` are enabled. Other
authorization/evidence/DFIR/static-analysis/intelligence/detection/advisory/planning entries remain
`planned`. Dynamic observation, debugging, .NET runtime work, and C2 emulation are `requires_lab`.
`redteam.exercise` is `disabled`. Capabilities are non-transitive: defensive intent does not grant
active testing, and `RE_STATIC` does not grant `RE_DYNAMIC_LAB`.

## Disposable lab backend

Templar delegates sandbox ownership to the sibling `drone` service. `GET /api/labs` reports Drone's
provider capabilities and returns a fail-closed unavailable record when Drone is disabled or cannot
be reached. Public wire types, v1 invariants, runtime response validation, URL policy,
authentication, and bounded response handling come from `@agentic-orch/drone-client`. The client enforces a
hard deadline even if the transport ignores abort, requests identity encoding, rejects compression
and redirects, cancels rejected bodies, and reconciles `Content-Length` when present. It correlates
artifact/job identities and submitted operation inputs, and verifies downloaded bytes against their
requested SHA-256 artifact ID. Templar keeps only its application-specific error mapping and
fail-closed unavailable status. Templar no longer constructs or executes Parallels commands.

Accepted source fixes have one narrow dynamic seam. It is disabled until
`TEMPLAR_DRONE_SOURCE_VALIDATION_OPERATION_ID` names an enabled Drone operation whose public contract
requires a `source` input with media type `application/vnd.templar.source-tree+json`, requires an
`application/json` `validation` output, and declares `network: none`. The static fix must pass its
evaluator and pinned audit, receive a promotion acknowledgment, and then receive a separate replay
rationale. Templar stages the accepted tree by content hash and submits only the registered operation
ID plus artifact ID; candidates cannot supply commands, images, environment, resources, or network
settings.

Drone's Apple-native provider runs Linux operations in one lightweight VM per job with no network
interface, read-only OCI roots, bounded writable storage, and fixed-size ext4 artifact exchange.
Parallels can later be added inside Drone as a Windows-only provider without changing Templar's
workflow boundary. Other dynamic workflows remain `requires_lab` until they gain the same
declared-operation and approval integration.

## Evaluation and promotion

`telecom_incident` retains its four-round researcher/candidate/reviewer flow. Security triage is
deliberately leaner: one read-only researcher, two isolated analysts, then deterministic selection in
three rounds and three agent turns. Exercise solving uses the same three-turn shape with one
question-to-evidence researcher and two independent solvers. Neither workflow adds an audit-agent
round.

Source audit uses five rounds: one complete attack-surface recon, three parallel hunt tracks
(injection, navigation/boundaries, and authorization/state/resources), two independent falsifiers,
two candidate-pinned auditors, then deterministic selection. A finding must retain a concrete source
trace and pass all five gates: unintended behavior, production reachability, attacker control,
context-specific defense failure, and new attacker capability. Dynamic reproduction remains a
separately approved Drone operation.

Source fix uses four rounds: one read-only root-cause and variant planner, two independent isolated
patch candidates, two candidate-pinned auditors, then deterministic selection. Its evaluator rejects
unmanifested files, unsupported filesystem objects, oversized or non-text changes, incomplete
finding coverage, unlinked implementation changes, missing regression tests, and any candidate-side
claim that project code or Drone validation ran. The evaluator checks structure and scope; the pinned
auditor judges whether the patch actually removes the root cause and whether the regression would
distinguish vulnerable from fixed behavior.

Agent Blocks runs the declared local evaluator against each candidate snapshot. Templar selects the highest
passing coverage score and breaks an exact tie by candidate ordinal (`candidate_a` before
`candidate_b`). The PCAP security evaluator checks known observation, principle, unknown, check, and
passive-action IDs and rejects definitive packet-only claims. The source evaluator requires complete
production-file and surface-hint disposition, valid source locations, all five gates for every
finding, and an unchanged target tree. These evaluators enforce contracts and coverage; the scoped
hunt/falsification/review agents perform the semantic analysis.

High-impact or security results set a human promotion gate. A model cannot acknowledge it; the local
operator performs that action explicitly through the API or dashboard.

## Persistence and lifecycle boundaries

Each submission creates `TEMPLAR_HOME/incidents/<runId>` exclusively, populates deterministic inputs,
initializes Git, and commits the baseline. Telecom cases copy their versioned documents and policy;
security cases contain only bounded analyzer facts, the compact triage playbook, and evaluator inputs.
Exercise cases contain only the decoded snapshot and evaluator inputs; the artifact itself never
enters an agent worktree. Source-audit cases materialize only canonical snapshot files under
`target/`; target changes are rejected by the evaluator. Source-fix cases start from the same
content-addressed snapshot but accept only the selected isolated patch into that incident directory.
Candidate changes are applied only there with `apply: true`; Templar never applies to its own source
repository or an arbitrary caller path.

Only live Effect fiber handles are kept in memory. Historical list/detail/event state is replayed from
the harness journal. Cooperative cancellation records an interrupted terminal state. Release one does
not promise crash resume: a force-killed process may leave a queued/running orphan, and Templar never
resumes from model prose.

The dashboard polls only Templar routes. It cannot invoke Codex, Jira, the PCAP parser, or a knowledge
store directly; dispatch agents; calculate scores; select candidates; access host files; or perform a
promotion acknowledgment or Drone replay without an explicit user action.

## Content and security exclusions

The repository preserves only the original versioned telecom documents under `domain/v1/documents`.
It does not commit course PDFs/PPTX files, recordings, archives, assignments, screenshots, diagrams,
samples, executable payloads, answer keys, personal identifiers, or deanonymization steps. Generated
course snapshots, disassembly observations, runs, and optional local grading data remain in ignored
Templar state.

Unknown or sensitive samples and customer IOCs are never automatically uploaded. Protect
`TEMPLAR_HOME`: incident workspaces, raw PCAPs, harness journals, candidate patches, and reports may
contain operationally sensitive data. Local content hashes provide identity, not confidentiality.

## Quality gates

```bash
pnpm check      # format, oxlint, typecheck, secret scan, and Vitest
pnpm build      # production TypeScript emit
pnpm demo       # complete fake-runtime harness run; no billing
pnpm preflight  # coverage, package, and dependency gates
git diff --check
git status --short
```

See [QUALITY.md](QUALITY.md) for the pinned pnpm, coverage, dependency, package, secret, and local-hook
gates.

Tests generate tiny classic-PCAP, exercise, and source fixtures in code. They cover strict schemas;
URL/path/symlink rejection; artifact byte and packet limits; packet parsing; policy boundaries;
workspace initialization; evaluator contracts; deterministic selection; all five complete harness
workflows with an injected scripted runtime; isolated source fixes and explicit Drone replay; HTTP
routing; Drone fail-closed handling; dashboard
boundaries; and immutable acknowledgment. No test invokes Codex or consumes ChatGPT subscription
usage.
