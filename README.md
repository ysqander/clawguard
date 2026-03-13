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

Run static scanner benchmarks against the shared fixture corpus with:

```bash
pnpm bench:static
```

Override iterations for local tuning:

```bash
CLAWGUARD_BENCH_ITERATIONS=250 pnpm bench:static
```

The repository now includes the foundation, discovery pipeline, first static scanner, threat-intelligence client foundations, and a reusable fixture corpus for quality and performance validation. Current progress and remaining work are tracked in [docs/clawguard-development-plan.md](docs/clawguard-development-plan.md) and [docs/clawguard-ticket-breakdown.md](docs/clawguard-ticket-breakdown.md). The architecture decisions behind the current foundation live in [docs/adr/README.md](docs/adr/README.md).
