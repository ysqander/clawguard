# ClawGuard

ClawGuard is a local-first skill auditor for OpenClaw agents. This repository is structured as a `pnpm` monorepo from day one so the scanner, daemon, detonation runtime, reporting pipeline, and platform adapters can evolve independently without collapsing into one package.

ClawGuard answers "should this skill be present on the machine?" It does not act as a runtime tool-call authorization layer.

## Workspace layout

- `apps/cli`: user-facing `clawguard` commands
- `apps/daemon`: long-running daemon and orchestration loop
- `packages/contracts`: shared schemas and TypeScript contracts
- `packages/platform`: OS/runtime abstraction layer
- `packages/storage`: SQLite and artifact-store abstractions
- `packages/discovery`: OpenClaw detection and watcher entrypoints
- `packages/integrations`: ClawHub and VirusTotal clients
- `packages/scanner`: static analysis and scoring
- `packages/detonation`: Podman-first detonation runtime
- `packages/reports`: evidence normalization and report assembly
- `packages/fixtures`: reusable benign/malicious fixtures and benchmark inputs

## Getting started

```bash
pnpm install
pnpm lint
pnpm format:check
pnpm build
pnpm typecheck
pnpm test
```

## Release preflight

Run the launch-hardening preflight before cutting a release candidate:

```bash
pnpm release:check
```

This runs lint, format checks, build, typecheck, tests, and a smoke pass that boots the built daemon on a temporary socket and queries it through the built CLI.

## Operator flow

Use the built daemon and CLI directly during packaging or local operator validation:

```bash
node apps/daemon/dist/index.js
node apps/cli/dist/index.js status
node apps/cli/dist/index.js service install
node apps/cli/dist/index.js service status
node apps/cli/dist/index.js service uninstall
```

The `service` commands target the macOS `launchd` user service flow added in `CG-019`.

## Security caveats

- Podman is the default detonation runtime. Docker remains a compatibility adapter, not the primary path.
- VirusTotal and ClawHub are enrichment signals. A clean lookup is not proof that a skill is safe.
- Detonation reduces risk by exercising setup and workflow behavior in a sandbox; it does not prove safety.

## Benchmark workflow

Run the observational static scanner benchmark against the shared fixture corpus with:

```bash
pnpm bench:static
```

Run the gated variant, which exits nonzero if any fixture exceeds the default `p95 <= 2000ms` budget:

```bash
pnpm bench:static:ci
```

Override iterations for local tuning:

```bash
CLAWGUARD_BENCH_ITERATIONS=250 pnpm bench:static
```

Override the gated budget in local enforcement runs:

```bash
CLAWGUARD_BENCH_STATIC_P95_BUDGET_MS=1500 pnpm bench:static:ci
```

Run the detonation preflight benchmark, which verifies fixture loading, runtime detection, and deterministic request construction without claiming full sandbox execution coverage:

```bash
pnpm bench:detonation:preflight
```

Run the full detonation benchmark, which exercises the existing prompt runner and report-synthesis path for every detonation fixture when Podman or Docker is available, and otherwise reports a safe `runtime-unavailable` summary:

```bash
pnpm bench:detonation
```

Run the gated variant, which exits nonzero when an available runtime records fixture execution failures or exceeds the configured per-fixture budget:

```bash
pnpm bench:detonation:ci
```

Override the gated budget for local enforcement runs:

```bash
CLAWGUARD_BENCH_DETONATION_BUDGET_MS=60000 pnpm bench:detonation:ci
```

The repository now includes the foundation, discovery pipeline, first static scanner, threat-intelligence client foundations, and a reusable fixture corpus with gated static and detonation benchmark harnesses. Current progress and remaining work are tracked in [docs/clawguard-development-plan.md](docs/clawguard-development-plan.md) and [docs/clawguard-ticket-breakdown.md](docs/clawguard-ticket-breakdown.md). The architecture decisions behind the current foundation live in [docs/adr/README.md](docs/adr/README.md).
