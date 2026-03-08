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
- `packages/fixtures`: test fixtures and benchmark inputs

## Getting started

```bash
pnpm install
pnpm build
```

The scaffold intentionally contains compileable placeholders only. Feature work should follow the workstreams and tickets in [docs/clawguard-development-plan.md](/Users/alexanderadamov/Documents/macbook/Programming/clawguard/docs/clawguard-development-plan.md) and [docs/clawguard-ticket-breakdown.md](/Users/alexanderadamov/Documents/macbook/Programming/clawguard/docs/clawguard-ticket-breakdown.md).

