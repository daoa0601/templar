# Templar

Templar is a local, policy-gated network and security analysis application built on the sibling
`aiur-orchestrator` package. It ships two workflows: `telecom_incident` for bounded packet-loss
diagnosis and `pcap_security_triage` for passive security analysis of one locally staged classic
PCAP. Both use explicit Aiur roles, isolated candidate worktrees, a local evaluator, and mechanical
candidate selection.

Templar is a single-user local system, not a production or multi-tenant security boundary.

## Architecture

```text
browser or CLI
  -> Templar loopback HTTP application
       -> strict workflow-specific decoder
       -> content-addressed classic-PCAP store and bounded parser
       -> dedicated committed incident Git repository
       -> aiur-orchestrator
            -> read-only evidence researcher
            -> candidate_a and candidate_b in isolated writable worktrees
            -> trusted deterministic evaluator for each snapshot
            -> optional candidate-pinned reviewers (telecom only)
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
- A locally authenticated `codex` CLI for real agent runs

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

# Run DonBot through the complete three-round harness with the scripted runtime.
pnpm smoke:ctu13:harness

# Run the compiled server.
pnpm build
pnpm start
```

The smoke commands download the captures into ignored local state under `.templar/smoke/ctu13`.
The harness variant stages DonBot through the artifact store, workspace, Aiur loop, evaluator,
selection guard, and result projection without invoking a model.

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
| `TEMPLAR_MAX_PCAP_PACKETS` |      `50000` | Packet parsing cap.                                         |

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
artifact atomically, rejects symlinks, and resolves artifacts only beneath its configured root. There
is no URL download, caller filename, or local-path API.

Security triage has a smaller fixed-purpose input. The route selects the workflow; callers cannot
submit a prompt or workflow ID in the body:

```json
{
  "schema_version": "1",
  "pcap_artifact_id": "pcap_sha256_<64 lowercase hex characters>"
}
```

Routes:

| Method and path                                 | Purpose                                                  |
| ----------------------------------------------- | -------------------------------------------------------- |
| `GET /`                                         | Static Templar dashboard.                                |
| `GET /health/live`                              | Process liveness.                                        |
| `GET /health/ready`                             | Local storage readiness.                                 |
| `GET /api/workflows`                            | Typed workflow catalog and release states.               |
| `POST /api/artifacts/pcap`                      | Stage one classic PCAP binary.                           |
| `POST /api/incidents`                           | Compatibility alias for a telecom incident run.          |
| `POST /api/workflows/telecom_incident/runs`     | Start a strictly decoded telecom incident run.           |
| `POST /api/workflows/pcap_security_triage/runs` | Start passive security triage of one staged PCAP.        |
| `GET /api/runs`                                 | Newest-first persisted run list.                         |
| `GET /api/runs/:runId`                          | Persisted run projection and budget usage.               |
| `GET /api/runs/:runId/events?after=N`           | Cursor-based redacted event timeline.                    |
| `GET /api/runs/:runId/result`                   | Accepted output, evaluator result, and promotion status. |
| `POST /api/runs/:runId/cancel`                  | Interrupt a fiber owned by this process.                 |
| `POST /api/runs/:runId/acknowledge`             | Persist an immutable human promotion acknowledgment.     |

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

`telecom_incident` and `pcap_security_triage` are enabled. Authorization/evidence/DFIR/static
analysis/intelligence/detection/advisory/planning entries remain `planned`. Dynamic observation,
debugging, .NET runtime work, and C2 emulation are `requires_lab`. `redteam.exercise` is `disabled`.
Capabilities are non-transitive: defensive intent does not grant active testing, and `RE_STATIC` does
not grant `RE_DYNAMIC_LAB`.

## Evaluation and promotion

`telecom_incident` retains its four-round researcher/candidate/reviewer flow. Security triage is
deliberately leaner: one read-only researcher, two isolated analysts, then deterministic selection in
three rounds and three agent turns. It has no audit-agent round.

For both workflows, Aiur runs the declared local evaluator against each candidate snapshot. Templar
selects the highest passing coverage score and breaks an exact tie by candidate ordinal
(`candidate_a` before `candidate_b`). The security evaluator checks known observation, principle,
unknown, check, and passive-action IDs; rejects active mutations and definitive packet-only claims;
and scores observation/unknown/action coverage. It does not grade prose style.

High-impact or security results set a human promotion gate. A model cannot acknowledge it; the local
operator performs that action explicitly through the API or dashboard.

## Persistence and lifecycle boundaries

Each submission creates `TEMPLAR_HOME/incidents/<runId>` exclusively, populates deterministic inputs,
initializes Git, and commits the baseline. Telecom cases copy their versioned documents and policy;
security cases contain only bounded analyzer facts, the compact triage playbook, and evaluator inputs.
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
identifiers, or deanonymization steps. Templar contains only its own compact triage playbook and
bounded packet-analysis contracts.

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
Hypothesis separation; telecom and security evaluator behavior; candidate selection; workspace
initialization; both complete harness workflows with an injected scripted runtime; strict HTTP
routing; dashboard boundaries; and immutable acknowledgment. No test invokes Codex or consumes
ChatGPT subscription usage.
