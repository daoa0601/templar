# Templar quality gates

This repository uses pnpm 11.13.1 exclusively. The exact version is pinned in `package.json`; installs made with npm, Yarn, Bun, or a different pnpm version fail at the repository boundary.

## Setup

```bash
pnpm --version
pnpm install --frozen-lockfile
pnpm hooks:install
```

Use a supported Node.js release from `package.json`. A verified CI or clean-room run must use
`pnpm install --frozen-lockfile`; with the current lock, that command also requires every sibling
listed below.

## Shared TypeScript policy

Templar consumes the `workspace:*` `@agentic-orch/ts-quality` development package for the repository secret
scan, package-manifest validation, managed Git-hook templates, strict Node.js TypeScript baseline,
and Prettier defaults. The repository-level commands below remain stable; their shared mechanics
delegate to `ts-quality` so fixes land once and are inherited on the next reviewed package update.

The small `scripts/quality/require-pnpm.mjs` preinstall guard remains local by design: an external
development dependency is not available yet when a clean install enters `preinstall`. Coverage
floors, smoke suites, build behavior, and dependency policy remain owned by Templar.

The expanded GitHub Actions jobs remain checked in because a relative reusable workflow cannot cross
these independent Git repository boundaries. Templar-specific dependency setup, coverage, and
integration jobs remain local.

## Gate ladder

| Command                | Purpose                                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------------------- |
| `pnpm quality:quick`   | Prettier check, warning-free Oxlint, strict TypeScript, and repository secret scan.                       |
| `pnpm check`           | Quick gate plus the deterministic unit/integration test suite.                                            |
| `pnpm quality:offline` | Quick gate, coverage thresholds, production build, and dry-run package manifest inspection.               |
| `pnpm deps:check`      | Production advisory audit at high severity and registry-signature verification. Requires registry access. |
| `pnpm preflight`       | Complete offline and online gate; this is the handoff/release command.                                    |

Coverage is measured over all `src/**/*.ts` files, including currently untested entrypoints. The enforced global floor is 75% statements, 68% branches, 82% functions, and 78% lines. Raising a floor is welcome; lowering one requires an explicit rationale.

The deterministic suite exercises the whole-course workflow with a scripted runtime and validates
the versioned five-assignment/33-requirement corpus, analyzers, evidence composition, sealed-grader
contract, security-team guard, and candidate evaluator. Real Codex and OpenCode model runs are
opt-in evaluations: they consume external subscription/provider usage, may take up to the declared
one-hour course budget, and are never part of CI or `pnpm preflight`.

`pnpm hooks:install` installs the package-owned managed hooks into this checkout's active Git hooks
directory:

- pre-commit runs `pnpm quality:quick`;
- pre-push runs `pnpm quality:offline`.

The hooks are a fast local feedback layer, not the source of truth. Automation should repeat the
frozen install and `pnpm preflight`.

## Local sibling-lock and CI status

The manifest contains `workspace:*` dependencies and the current lock resolves four sibling modules:

| Sibling                         | Current role                                                      |
| ------------------------------- | ----------------------------------------------------------------- |
| `@agentic-orch/agent-blocks`    | Runtime orchestration and public control-plane contracts.         |
| `@agentic-orch/drone-client`    | Public Drone v1 contracts and hardened bounded HTTP client.       |
| `@agentic-orch/node-guardrails` | Neutral bounded HTTP and verified content-addressed byte storage. |
| `@agentic-orch/ts-quality`      | Development-only repository checks and shared configuration.      |

Every `pnpm install --frozen-lockfile` therefore requires all four checkouts at the relative paths
in `pnpm-workspace.yaml`. The checked-in workflow recreates that layout at audited full commit SHAs,
builds Node Guardrails before Agent Blocks, builds the remaining runtime modules, and then runs
Templar's frozen install and gates. Local validation uses the same sibling layout. Source repository
visibility does not imply npm publication.

## Dependency and supply-chain policy

`pnpm-workspace.yaml` enforces:

- exact dependency saves and an exact pnpm version;
- Node engine and peer-dependency compatibility;
- frozen lockfiles in CI;
- a strict 24-hour minimum package release age;
- rejection of transitive Git/tarball dependencies;
- explicit review of every dependency lifecycle script;
- dependency-state verification before scripts run.

Only `esbuild` is approved to execute a third-party install script. Optional native acceleration from `msgpackr-extract` is explicitly denied. Any new lifecycle script makes installation fail until it is reviewed and recorded in `allowBuilds`.

## Secret scan scope

The shared scanner examines staged Git blobs, their current working-tree copies, and unignored
untracked files for secret-bearing filenames, private keys, common provider token formats, and
non-placeholder secret assignments in configuration files. It never follows symlinks, bounds file
reads, and reports only escaped file and line metadata—never the matched value. This supplements
host and repository secret-scanning controls; it does not replace them.
