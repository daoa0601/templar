# Templar quality gates

This repository uses pnpm 11.13.1 exclusively. pnpm enforces it natively through `packageManager`
and `engines.pnpm` in `package.json` plus `engineStrict` and `pmOnFail: error` in
`pnpm-workspace.yaml`; npm cannot resolve the `workspace:*` dependencies.

## Setup

```bash
pnpm --version
pnpm install --frozen-lockfile
pnpm hooks:install
```

Use a supported Node.js release from `package.json`. A verified CI or clean-room run must use
`pnpm install --frozen-lockfile`.

## Shared TypeScript policy

Templar uses the sibling `@agentic-orch/ts-quality` development module for the repository secret
scan, managed Git-hook templates, strict Node.js TypeScript baseline, and Prettier defaults. The
repository-level commands below remain stable; their shared mechanics delegate to `ts-quality` so
fixes land once. Coverage floors, smoke suites, build behavior, and dependency policy remain owned
by Templar.

## Gate ladder

| Command                | Purpose                                                                                                   |
| ---------------------- | --------------------------------------------------------------------------------------------------------- |
| `pnpm quality:quick`   | Prettier check, warning-free Oxlint, strict TypeScript, and repository secret scan.                       |
| `pnpm check`           | Quick gate plus the deterministic unit/integration test suite.                                            |
| `pnpm quality:offline` | Quick gate, coverage thresholds, and production build.                                                    |
| `pnpm deps:check`      | Production advisory audit at high severity and registry-signature verification. Requires registry access. |
| `pnpm preflight`       | Complete offline and online gate; this is the handoff command.                                            |

Coverage is measured over all `src/**/*.ts` files, including currently untested entrypoints. The enforced global floor is 75% statements, 68% branches, 82% functions, and 78% lines. Raising a floor is welcome; lowering one requires an explicit rationale.

The deterministic suite exercises the whole-course workflow with a scripted runtime and validates
the versioned five-assignment/33-requirement corpus, analyzers, evidence composition, sealed-grader
contract, security-team guard, and candidate evaluator. Real Codex and OpenCode model runs are
opt-in evaluations: they consume external subscription/provider usage, may take up to the declared
one-hour course budget, and are never part of CI or `pnpm preflight`.

Course-lab tests use a fake Drone transport. They prove approval-before-upload, live attestation
matching, strict operation shape, private custody, job/input correlation, assignment-evidence
validation, and per-job execution-attestation correlation without executing a specimen or invoking a
model provider.

`pnpm hooks:install` installs the package-owned managed hooks into this checkout's active Git hooks
directory:

- pre-commit runs `pnpm quality:quick`;
- pre-push runs `pnpm quality:offline`.

The hooks are a fast local feedback layer, not the source of truth. Automation should repeat the
frozen install and `pnpm preflight`.

## Siblings

`agent-blocks`, `drone-client`, `node-guardrails`, and `ts-quality` must be checked out next to this
repository; see the catalog README for the layout. The lock resolves them as `link:` entries, so a
missing sibling fails the frozen install instead of falling back to a registry. The GitHub workflow
checks them out at their default branch, and `pnpm install` builds `node-guardrails`,
`agent-blocks`, and `drone-client` through their `prepare` scripts, in dependency order.

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
