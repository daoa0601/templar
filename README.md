# Templar

Templar is a local, policy-gated network and security analysis application built on the sibling
`aiur-orchestrator` package. The first release enables one workflow,
`telecom_incident`: it validates a bounded incident, optionally analyzes one locally staged classic
PCAP, creates a dedicated Git evidence workspace, asks the harness for two isolated candidate
diagnoses, evaluates and audits them, and applies only the mechanically selected candidate to that
incident workspace.

Templar is a single-user local system, not a production or multi-tenant security boundary.

## Architecture

```text
browser or CLI
  -> Templar loopback HTTP application
       -> strict incident decoder
       -> content-addressed classic-PCAP store and bounded parser
       -> dedicated committed incident Git repository
       -> aiur-orchestrator
            -> read-only evidence researcher
            -> candidate_a and candidate_b in isolated writable worktrees
            -> trusted deterministic evaluator for each snapshot
            -> candidate-pinned read-only evaluation auditors
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
- A built sibling checkout at `../aiur-orchestrator`
- A locally authenticated `codex` CLI only for the real `sample` command

```bash
cd templar
pnpm install --frozen-lockfile
pnpm check
pnpm build
```

The package dependency is deliberately local:

```json
"aiur-orchestrator": "file:../aiur-orchestrator"
```

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

# Run the compiled server.
pnpm build
pnpm start
```

The smoke command downloads the captures into ignored local state under `.templar/smoke/ctu13` and
prints the services, port-aware conversations, source fan-out, and TCP signals available to future
security workflows.

Configuration:

| Variable                   |      Default | Meaning                                                     |
| -------------------------- | -----------: | ----------------------------------------------------------- |
| `TEMPLAR_HOST`             |  `127.0.0.1` | HTTP bind host. Non-loopback requires a token.              |
| `TEMPLAR_PORT`             |       `8080` | HTTP port.                                                  |
| `TEMPLAR_HOME`             | `~/.templar` | Incident, artifact, acknowledgment, and harness state root. |
| `TEMPLAR_BEARER_TOKEN`     |        unset | Optional in loopback development; required otherwise.       |
| `TEMPLAR_MAX_ACTIVE_RUNS`  |          `2` | Process-local active-run admission cap.                     |
| `TEMPLAR_MAX_JSON_BYTES`   |      `65536` | JSON request-body cap.                                      |
| `TEMPLAR_MAX_PCAP_BYTES`   |    `8388608` | PCAP upload and analysis byte cap.                          |
| `TEMPLAR_MAX_PCAP_PACKETS` |      `10000` | Packet parsing cap.                                         |

Callers cannot choose a workspace, evaluator command, Codex setting, executable, budget, URL, or host
path through incident input.

## Incident and artifact API

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
artifact atomically, rejects symlinks, and resolves artifacts only beneath its configured root. There
is no URL download, caller filename, or local-path API.

Routes:

| Method and path                       | Purpose                                                                         |
| ------------------------------------- | ------------------------------------------------------------------------------- |
| `GET /`                               | Static Templar dashboard.                                                       |
| `GET /health/live`                    | Process liveness.                                                               |
| `GET /health/ready`                   | Local storage readiness.                                                        |
| `GET /api/workflows`                  | Typed workflow catalog and release states.                                      |
| `POST /api/artifacts/pcap`            | Stage one classic PCAP binary.                                                  |
| `POST /api/incidents`                 | Validate input, create a workspace/run, return `202` after durable observation. |
| `GET /api/runs`                       | Newest-first persisted run list.                                                |
| `GET /api/runs/:runId`                | Persisted run projection and budget usage.                                      |
| `GET /api/runs/:runId/events?after=N` | Cursor-based redacted event timeline.                                           |
| `GET /api/runs/:runId/result`         | Accepted applied output, structured audit, and promotion status.                |
| `POST /api/runs/:runId/cancel`        | Interrupt a fiber owned by this process.                                        |
| `POST /api/runs/:runId/acknowledge`   | Persist an immutable human promotion acknowledgment.                            |

When configured, send `Authorization: Bearer <TEMPLAR_BEARER_TOKEN>` to every `/api/*` route. Health
and static assets remain available without it. Errors use stable redacted JSON codes.

## Evidence, findings, and hypotheses

Templar keeps three data classes separate:

- `EvidenceItem` records an immutable source identity, SHA-256, acquisition availability, context,
  sensitivity, parser version, provenance, and typed facts.
- `Finding` is a reproducible rule result referencing evidence IDs, fact IDs, and exact
  document/section citations.
- `Hypothesis` is an interpretation referencing findings, with confidence, alternatives, and
  unresolved evidence needs.

Rendered prose never becomes evidence. A ticket reference that was not retrieved remains an explicit
gap. Packet parser failures and unavailable checks likewise cannot become a clean verdict.

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

`telecom_incident` is the only `enabled` release-one workflow. Authorization/evidence/DFIR/static
analysis/intelligence/detection/advisory/planning entries are visible as `planned`. Dynamic observation,
debugging, .NET runtime work, and C2 emulation are `requires_lab`. `redteam.exercise` is `disabled`.
Capabilities are non-transitive: defensive intent does not grant active testing, and `RE_STATIC` does
not grant `RE_DYNAMIC_LAB`.

## Evaluation, audit, and promotion

The bounded evaluation stack is intentionally redundant:

The enabled workflow permits four rounds, five logical agents/agent turns, two concurrent agents,
180 seconds per turn, 600 seconds total, and 500,000 budget-charged tokens. Token budgeting counts
fresh (non-cached) input plus output; raw and cached counts remain in private runtime events.

1. Each candidate writes only `result.json` and `report.md`, runs the declared local evaluator,
   inspects its JSON gates/coverage, fixes those outputs, and reruns within one finite harness turn.
2. The harness independently runs its trusted evaluator copy after every candidate snapshot.
3. The evaluator hard-rejects invalid schema, unknown evidence/rules/citations, changed metrics,
   policy-inconsistent severity, hidden boundary ambiguity, unsupported or uncited actions,
   unavailable-check claims, external mutation, and missing audit/promotion fields.
4. Passing candidates receive a numeric set-coverage score: 50% required evidence, 30% ordered SOP
   steps, and 20% acknowledged unknowns.
5. A read-only `evaluation_auditor` is pinned to each candidate. It reruns the evaluator, reads the
   end-to-end candidate diff, evaluator contract, and harness-created `.harness-audit/trace.jsonl`,
   and explicitly checks hardcoding, cache reuse, grader detection, path/environment tricks,
   unsupported claims, and evidence/benchmark gaming. Machine control markers are exact standalone
   entries; explanatory prose is kept in separate findings so punctuation cannot silently alter a gate.
6. Missing or malformed audit markers, `audit.disposition=manual_review`, absent traces, and trace
   headers with `truncated=true` all degrade to manual review.
7. Templar's runtime selection guard replays only trusted harness evaluator projections. It permits
   acceptance only after both pinned auditors, chooses the highest passing score, and breaks exact
   ties by fixed candidate ordinal (`candidate_a` before `candidate_b`). Model prose cannot change the
   score or tie-break.

The final API returns a structured `evaluationAudit` projection, not raw private reports or traces.
High-impact, security, headline, active-testing, or degraded-audit outcomes set a human promotion
gate. A model, unit test, or audit agent cannot acknowledge it. The acknowledgment is created once
with exclusive file creation; retrying the identical rationale is idempotent, while a different
rationale cannot overwrite the record.

## Persistence and lifecycle boundaries

Each submission creates `TEMPLAR_HOME/incidents/<runId>` exclusively, populates deterministic inputs,
copies the two versioned telecom documents and policy, initializes Git, and commits the baseline.
Candidate changes are applied only there with `apply: true`; Templar never applies to its own source
repository or an arbitrary caller path.

Only live Effect fiber handles are kept in memory. Historical list/detail/event state is replayed from
the harness journal. Cooperative cancellation records an interrupted terminal state. Release one does
not promise crash resume: a force-killed process may leave a queued/running orphan, and Templar never
resumes from model prose.

The dashboard polls only Templar routes. It cannot invoke Codex, Jira, the PCAP parser, or a knowledge
store directly; dispatch agents; calculate scores; select candidates; access host files; or perform a
promotion acknowledgment without an explicit user action.

## Content and security exclusions

The repository preserves only the original versioned telecom documents under `domain/v1/documents`.
It does not copy course PDFs/PPTX files, recordings, archives, assignments, screenshots, diagrams,
samples, executable payloads, disassembly listings, decryption code, exploit commands, personal
identifiers, or deanonymization steps. Course-derived concepts are represented as original Templar
schemas, policies, gates, and provenance citations.

Unknown or sensitive samples and customer IOCs are never automatically uploaded. Protect
`TEMPLAR_HOME`: incident workspaces, raw PCAPs, harness journals, candidate patches, and reports may
contain operationally sensitive data. Local content hashes provide identity, not confidentiality.

## Verification

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

Tests generate tiny classic-PCAP fixtures in code. They cover strict schemas; URL/path rejection;
artifact digest/symlink/format/byte/packet gates; pure ACK, retransmission, RST, zero-window, UDP/TCP
DNS QR, and fragment behavior; 3%/7% policy boundaries; stable corpus IDs; EvidenceItem/Finding/
Hypothesis separation; evaluator hard gates and scores; candidate selection; private audit projection;
workspace initialization; the full real-harness workflow with an injected scripted runtime; HTTP
auth/body/run/event/result/cancellation routes; dashboard boundaries; and immutable acknowledgment.
No test invokes Codex or consumes ChatGPT subscription usage.
