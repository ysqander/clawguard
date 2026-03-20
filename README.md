# ClawGuard

ClawGuard is a local-first skill auditor for OpenClaw agents.

It answers one question:

> Should this skill be present on the machine?

ClawGuard is not a runtime tool-call authorization layer. It focuses on pre-install and post-detection analysis of local skills through static analysis, behavioral detonation, reporting, quarantine, and operator review.

## Status

- `0.1.0`
- macOS-first
- local-first
- Podman-first behavioral runtime, with Docker compatibility

## What ClawGuard Does

ClawGuard is built for OpenClaw users who want to inspect local OpenClaw skills before trusting them.

Today it can:

- discover OpenClaw skill roots from local configuration
- watch skill directories for changes
- statically inspect `SKILL.md`, helper scripts, and related files
- normalize visible, hidden, and decoded content into reusable threat signals
- block or review suspicious skills before install-time trust
- detonate skills in a sandbox to exercise setup flows and representative workflows
- preserve local evidence artifacts, reports, and scan history
- expose both a CLI and a local daemon for ongoing monitoring

## How It Thinks

ClawGuard uses two complementary layers:

1. Static analysis

This reads the skill without executing it. It is good at catching things like staged download chains, prompt overrides, secret access instructions, memory tampering, obfuscation, and suspicious setup scripts.

2. Behavioral detonation

This runs the skill in a sandbox and watches what actually happens. It is good at catching setup-time downloads, honeypot access, secret exfiltration, persistent instruction injection, reverse-shell behavior, and credential harvesting.

Behavioral detonation reduces risk. It does not prove a skill is safe.

## Threat Coverage Snapshot

As of `2026-03-20`, using the corpus in [docs/clawguard-threat-scenarios.md](docs/clawguard-threat-scenarios.md) and the fixture registry in [packages/fixtures/src/index.ts](packages/fixtures/src/index.ts):

- static scanner coverage: `10/10` malicious threat fixtures blocked
- live detonation coverage in Docker: `5/5` malicious runtime-backed fixtures blocked
- live detonation coverage in Podman: `5/5` malicious runtime-backed fixtures blocked
- benign live control: `allow` in both Docker and Podman

Threat classes currently covered by the shipped corpus include:

- staged download and execute chains
- local secret and credential exfiltration
- persistent `MEMORY.md` and `SOUL.md` poisoning
- hidden prompt-injection overrides
- obfuscated payloads in comments, invisible Unicode, and encoded text
- fake password dialogs and credential harvesting

The current runtime-backed results also show parity between Docker and Podman on the live detonation subset.

## Requirements

### Core requirements

- Node `>=22`
- macOS for the current daemon and service-management flow

### Development requirements

- `pnpm`

### Detonation runtime requirements

If you want behavioral detonation, you need at least one supported container runtime installed:

- Podman: preferred and default
- Docker: supported compatibility path

If neither runtime is installed, ClawGuard can still do discovery, static scanning, reporting, audit history, and quarantine workflows. The `detonate` command will return a clear runtime-unavailable error instead of failing silently.

## Runtime Advice

ClawGuard is intentionally Podman-first. That is the runtime the project is designed around, and Docker support exists so the same behavioral contract can still run on hosts where Docker is the easier operational choice.

On macOS, Podman may require extra setup depending on how it was installed and which VM backend it is using. If Podman on Apple Silicon is unstable under `applehv`, a `libkrun` setup can be a better fit.

Typical Podman-on-macOS setup looks like:

```bash
brew install podman
podman machine init
podman machine start
```

If you need the `libkrun` path:

```bash
brew tap slp/krun
brew install krunkit
```

Then set:

```toml
[machine]
provider="libkrun"
```

in `~/.config/containers/containers.conf`, recreate the machine, and start it again.

Docker users only need a healthy local Docker daemon.

## Installation

Install the published CLI:

```bash
npm install -g clawguard
```

Start the daemon in the foreground:

```bash
clawguard daemon
```

In another terminal, inspect daemon health:

```bash
clawguard status
```

## Typical Workflow

A normal workflow is:

1. Start the daemon.
2. Scan a local skill directory.
3. Read the unified report.
4. Detonate the skill if you want behavioral evidence.
5. Allow or block the skill based on the findings.

Example:

```bash
clawguard daemon
clawguard scan ~/.openclaw/workspace/skills/example-skill --detailed
clawguard report example-skill --detailed
clawguard detonate example-skill --detailed
```

## CLI Overview

ClawGuard has a small command set:

- `clawguard daemon`
  Starts the local daemon in the foreground.
- `clawguard status`
  Shows daemon health, watcher state, and active jobs.
- `clawguard scan <skill-path> [--detailed]`
  Runs an immediate static scan on a skill directory.
- `clawguard report <slug> [--detailed]`
  Shows the latest static and detonation view for a skill.
- `clawguard detonate <slug> [--detailed]`
  Runs behavioral detonation for a locally resolvable skill.
- `clawguard allow <slug> [reason] [--detailed]`
  Records an explicit operator allow decision.
- `clawguard block <slug> [reason] [--detailed]`
  Records an explicit operator block decision.
- `clawguard audit`
  Lists recent scan history.
- `clawguard service install|status|uninstall`
  Manages the macOS `launchd` user service.

## Output You Should Expect

Static analysis reports are designed to answer:

- what ClawGuard saw
- which rule IDs fired
- what evidence supported those findings
- whether the skill should be allowed, reviewed, or blocked

Behavioral reports are designed to answer:

- what the sandbox executed
- what network, file, and memory side effects occurred
- whether honeypots or decoys were touched
- whether the behavior is consistent with staged malware, exfiltration, credential harvesting, or persistence

## Development

Install dependencies:

```bash
pnpm install
```

Run the normal validation flow:

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

## Benchmarks and Validation

ClawGuard ships benchmark and corpus validation commands for both static and detonation coverage.

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

Release validation:

```bash
pnpm release:check
```

## Monorepo Layout

- `apps/cli`: user-facing `clawguard` command
- `apps/daemon`: daemon and orchestration loop
- `packages/contracts`: shared schemas and payloads
- `packages/platform`: OS and runtime abstraction layer
- `packages/storage`: SQLite and artifact store
- `packages/discovery`: OpenClaw discovery and watcher pipeline
- `packages/integrations`: ClawHub and VirusTotal clients
- `packages/scanner`: static analysis, normalized signal extraction, and scoring
- `packages/detonation`: sandbox runtime, prompt runner, telemetry capture, and behavioral verdicting
- `packages/reports`: report assembly and rendering
- `packages/fixtures`: benign and malicious regression corpus

## Security Notes

- Podman is the default detonation runtime. Docker is the compatibility path.
- VirusTotal and ClawHub are enrichment signals, not proof of safety.
- A clean marketplace reputation or missing remote verdict is not evidence that a skill is safe.
- Detonation reduces uncertainty by exercising setup and workflow behavior in a sandbox. It does not certify safety.
- ClawGuard is a local skill auditor, not a runtime authorization product.

## Documentation

- [Threat scenarios and corpus notes](docs/clawguard-threat-scenarios.md)
- [High-level development plan](docs/clawguard-development-plan.md)
- [Ticket breakdown](docs/clawguard-ticket-breakdown.md)
- [Architecture decision records](docs/adr/README.md)
- [IPC overview](docs/ipc-overview.md)
- [Release checklist](docs/release-checklist.md)
- [0.1.0 release notes draft](docs/releases/0.1.0.md)

## License

MIT
