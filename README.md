# ClawGuard

ClawGuard is a local-first skill auditor for OpenClaw agents.

It answers one question:

> Should this skill be present on the machine?

ClawGuard is not a runtime tool-call authorization layer. It focuses on pre-install and post-detection analysis of local skills through static analysis, behavioral detonation, reporting, quarantine, and operator review.

## Status

- `0.1.0`
- macOS-first
- local-first
- Podman-first detonation runtime, with Docker compatibility

## What It Does

- Discovers OpenClaw skill roots from local configuration.
- Watches local skill directories for changes.
- Runs static analysis against skill contents and setup scripts.
- Quarantines suspicious skills.
- Runs behavioral detonation in a sandbox for manual and automatic follow-up analysis.
- Stores scan history, reports, and evidence artifacts locally.
- Exposes a CLI plus a local daemon for ongoing monitoring.

## Requirements

- Node `>=22`
- `pnpm` for repo development
- macOS for the current service-management flow
- Podman recommended for detonation
- Docker supported as a compatibility runtime for detonation

## Installation

Install the published CLI:

```bash
npm install -g clawguard
```

Start the daemon in the foreground:

```bash
clawguard daemon
```

In another terminal:

```bash
clawguard status
```

## Quick Start

Scan a local skill by path:

```bash
clawguard scan /path/to/skill --detailed
```

Read the latest report for a known slug:

```bash
clawguard report my-skill --detailed
```

Run behavioral detonation for a locally installed skill:

```bash
clawguard detonate my-skill --detailed
```

Review recent scan activity:

```bash
clawguard audit
```

## CLI Commands

### `clawguard daemon`

Starts the local ClawGuard daemon in the foreground.

Use this for local testing, debugging, or when you do not want to install the macOS user service.

### `clawguard status`

Shows daemon health, active job count, watcher state, and any operator-visible issues.

### `clawguard scan <skill-path> [--detailed]`

Runs an immediate static scan on a skill directory.

- `--detailed` adds the full rendered report.
- Suspicious results may trigger quarantine.
- High-risk static results may also enqueue automatic detonation.

### `clawguard report <slug> [--detailed]`

Shows the unified operator view for a skill slug.

This is the main read path after a scan. It includes:

- the latest static report
- the latest detonation status
- the latest completed detonation report when one exists

### `clawguard detonate <slug> [--detailed]`

Runs behavioral detonation for a locally installed skill that ClawGuard can resolve from discovered OpenClaw roots.

- This is a manual operator action.
- It returns a behavioral report on success.
- If no supported runtime is available, it returns a clear runtime error instead of failing silently.

### `clawguard allow <slug> [reason] [--detailed]`

Records an operator allow decision for the latest known result for that slug.

### `clawguard block <slug> [reason] [--detailed]`

Records an operator block decision and keeps the skill out of the normal install path.

### `clawguard audit`

Lists recent scans from local history.

### `clawguard service install|status|uninstall`

Manages the macOS `launchd` user service for the ClawGuard daemon.

Typical flow:

```bash
clawguard service install
clawguard service status
clawguard service uninstall
```

## Example Operator Flow

```bash
clawguard daemon
clawguard status
clawguard scan ~/.openclaw/workspace/skills/example-skill --detailed
clawguard report example-skill --detailed
clawguard detonate example-skill --detailed
```

## Development

Install dependencies:

```bash
pnpm install
```

Run the standard local checks:

```bash
pnpm lint
pnpm format:check
pnpm build
pnpm typecheck
pnpm test
```

Run the built CLI and daemon directly from the repo:

```bash
node apps/cli/dist/index.js status
node apps/cli/dist/index.js daemon
```

## Monorepo Layout

- `apps/cli`: user-facing `clawguard` command
- `apps/daemon`: daemon and orchestration loop
- `packages/contracts`: shared schemas and payloads
- `packages/platform`: OS/runtime abstraction layer
- `packages/storage`: SQLite and artifact store
- `packages/discovery`: OpenClaw discovery and watcher pipeline
- `packages/integrations`: ClawHub and VirusTotal clients
- `packages/scanner`: static analysis and scoring
- `packages/detonation`: sandbox runtime and telemetry capture
- `packages/reports`: report assembly and rendering
- `packages/fixtures`: benign and malicious test fixtures

## Release Validation

Run the release gate before publishing:

```bash
pnpm release:check
```

This covers:

- lint
- format check
- typecheck
- workspace tests
- repo-built smoke validation
- packaged tarball install smoke validation

Build the publishable tarball directly:

```bash
pnpm release:pack
pnpm release:smoke:install
```

## Benchmarks

Static benchmark:

```bash
pnpm bench:static
pnpm bench:static:ci
```

Detonation benchmark:

```bash
pnpm bench:detonation:preflight
pnpm bench:detonation
pnpm bench:detonation:ci
```

## Security Notes

- Podman is the default detonation runtime. Docker is the compatibility path.
- VirusTotal and ClawHub are enrichment signals, not proof of safety.
- Behavioral detonation reduces risk by exercising setup and workflow behavior in a sandbox. It does not prove a skill is safe.
- ClawGuard is a local skill auditor, not a runtime authorization product.

## Documentation

- [High-level development plan](docs/clawguard-development-plan.md)
- [Ticket breakdown](docs/clawguard-ticket-breakdown.md)
- [Architecture decision records](docs/adr/README.md)
- [IPC overview](docs/ipc-overview.md)
- [Release checklist](docs/release-checklist.md)
- [0.1.0 release notes draft](docs/releases/0.1.0.md)

## License

MIT
