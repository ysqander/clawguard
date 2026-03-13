# ClawGuard

ClawGuard is a local-first skill auditor for OpenClaw agents. This repository is structured as a `pnpm` monorepo from day one so the scanner, daemon, detonation runtime, reporting pipeline, and platform adapters can evolve independently without collapsing into one package.

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

## Benchmark workflow

Run the observational static scanner benchmark against the shared fixture corpus with:

```bash
pnpm bench:static
```

Run the gated CI variant, which exits nonzero if any fixture exceeds the default `p95 <= 2000ms` budget:

```bash
pnpm bench:static:ci
```

Override iterations for local tuning:

```bash
CLAWGUARD_BENCH_ITERATIONS=250 pnpm bench:static
```

Override the gated budget in CI or local enforcement runs:

```bash
CLAWGUARD_BENCH_STATIC_P95_BUDGET_MS=1500 pnpm bench:static:ci
```

Run the detonation preflight benchmark, which verifies fixture loading, runtime detection, and deterministic request construction without claiming full sandbox execution coverage:

```bash
pnpm bench:detonation:preflight
```

The repository now includes the foundation, discovery pipeline, first static scanner, threat-intelligence client foundations, and a reusable fixture corpus with a gated static benchmark harness plus an initial detonation preflight harness. Current progress and remaining work are tracked in [docs/clawguard-development-plan.md](docs/clawguard-development-plan.md) and [docs/clawguard-ticket-breakdown.md](docs/clawguard-ticket-breakdown.md). The architecture decisions behind the current foundation live in [docs/adr/README.md](docs/adr/README.md).
