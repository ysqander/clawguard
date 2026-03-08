# AGENTS.md

This file is for future coding agents working in this repository. Treat it as the local operating manual for ClawGuard.

## Project intent

ClawGuard is a local-first skill auditor for OpenClaw agents. Its scope is pre-install and post-detection analysis of skills, not runtime tool-call mediation.

The key product question is:

- "Should this skill be present on the machine?"

Not:

- "Should this tool call execute right now?"

Do not drift the architecture toward APort-style runtime authorization.

## Current architecture decisions

These are already decided. Do not reopen them unless the user explicitly asks.

- Monorepo from day one.
- Canonical toolchain: `pnpm` + Node.
- Minimum Node engine: `>=22`.
- Do not switch this project to Bun as the primary runtime or package manager.
- macOS-first MVP.
- Linux support should come later by implementing platform interfaces, not by restructuring the repo.
- Podman is the default detonation runtime.
- Docker is a compatibility adapter, not the primary path.
- Persistence is hybrid:
  - SQLite for structured/queryable state.
  - Flat files for large or irregular artifacts.
- ClawHub and VirusTotal are enrichment signals, not the primary detection engine.

## Read these first

Before making architectural or feature changes, read:

- `README.md`
- `docs/clawguard-development-plan.md`
- `docs/clawguard-ticket-breakdown.md`

If the change touches scope, storage, integrations, detonation, or package boundaries, update the relevant docs in the same change.

## Repository layout

- `apps/cli`: user-facing `clawguard` command
- `apps/daemon`: long-running daemon and orchestration loop
- `packages/contracts`: source of truth for shared types and payload shapes
- `packages/platform`: OS/runtime abstraction layer
- `packages/storage`: SQLite and artifact-store layer
- `packages/discovery`: OpenClaw discovery, watcher pipeline, quarantine entrypoints
- `packages/integrations`: ClawHub and VirusTotal clients, caching, quotas
- `packages/scanner`: static analysis, rule engine, scoring
- `packages/detonation`: Podman-first detonation runtime
- `packages/reports`: evidence normalization and plain-language reporting
- `packages/fixtures`: benign/malicious fixtures and benchmark inputs

Apps should stay thin. Business logic belongs in packages.

## Package boundary rules

- Shared payloads belong in `packages/contracts`.
- OS-specific behavior belongs in `packages/platform`.
- Persistence primitives belong in `packages/storage`.
- External API clients belong in `packages/integrations`.
- The daemon should orchestrate; it should not absorb scanner, storage, or integration internals.
- The CLI should format and dispatch; it should not reimplement daemon logic.

If you find yourself adding logic to an app that could live in a package, move it.

## Storage rules

Use SQLite for:

- scan history
- quarantine state
- allowlist and blocklist hashes
- normalized report summaries
- daemon job metadata
- cached threat-intel verdict metadata
- indexes pointing to artifacts on disk

Use flat files for:

- raw `SKILL.md` snapshots
- raw analysis JSON
- detonation stdout/stderr
- network captures
- memory/file diffs
- rendered reports
- copied forensic artifacts

Rule of thumb:

- If it needs filtering, joining, deduping, or history queries, store it in SQLite.
- If it is large, irregular, append-only, or evidence-heavy, store it on disk and reference it from SQLite.

Do not put large blobs in SQLite unless there is a strong reason.

## Platform rules

- Implement macOS behavior first.
- Keep platform-specific APIs behind interfaces in `packages/platform`.
- Do not scatter `process.platform` checks throughout the codebase.
- Linux support should be added by implementing the platform contracts.

Current expectation for macOS:

- watcher support
- notifications
- `launchd` integration
- Podman runtime detection

## Detonation rules

- Podman is the default runtime.
- Docker support should implement the same runtime contract surface.
- The detonation environment must actively exercise staged-download workflows.
- Passive loading is not enough. Workflow malware often triggers only when the agent follows setup/install instructions.
- Preserve raw evidence artifacts from detonation runs.

Do not oversell detonation. It reduces risk; it does not prove safety.

## Threat-intelligence rules

ClawHub:

- Use it for metadata enrichment, remote `SKILL.md` retrieval, and verdict passthrough if available.
- Do not treat a clean or missing verdict as proof of safety.

VirusTotal:

- Hash lookups are acceptable on the blocking static path.
- File uploads must not block install-time decisions.
- URL/domain/IP enrichment is mainly for post-detonation reporting.
- Respect rate limits with caching, deduplication, and quota control.
- Present VT as one signal, not the final verdict.

## Build and verification commands

Use these as the default local checks:

```bash
pnpm install
pnpm build
pnpm typecheck
```

When changing the runnable entrypoints, also smoke test:

```bash
node apps/cli/dist/index.js
node apps/daemon/dist/index.js
```

If you add tests later, prefer wiring them into root `pnpm` scripts instead of ad hoc commands.

## Coding expectations

- Keep TypeScript strict.
- Prefer the Node standard library unless there is a clear need for a dependency.
- Add dependencies conservatively, especially native or platform-sensitive ones.
- Keep package APIs small and explicit.
- Favor plain data contracts over implicit cross-package coupling.
- Avoid magic paths and hardcoded OS behavior outside `packages/platform`.
- Keep reports readable for developers, not only security specialists.

## When making changes

- Preserve package boundaries.
- Update docs if you materially change architecture or scope.
- Verify the workspace builds before finishing.
- Do not introduce Bun-specific tooling.
- Do not silently swap Podman-first assumptions for Docker-first ones.

If a requested change conflicts with these rules, follow the user request, but call out the tradeoff explicitly.
