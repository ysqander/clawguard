# ClawGuard Ticket Breakdown

This ticket plan converts the high-level implementation plan into deliverable work. Ticket IDs are placeholders; rename them to match your tracker.

## Priority guide

- `P0`: required for Static MVP
- `P1`: required for Behavioral MVP
- `P2`: launch hardening or post-MVP improvement

## Current snapshot

As of 2026-03-18, the repo has landed the main code and documentation for `CG-001` through `CG-021`.

`CG-020` now covers the reusable fixture corpus plus gated static and full detonation benchmark harnesses.

Milestone A static-path coverage is complete after `CG-018` landed.

Milestone B behavioral validation coverage is complete after `CG-021` landed.

The next unfinished launch tickets now start with:

- `CG-022`: package release flow and launch docs

## Epic A: Monorepo Foundation

### CG-001 Initialize the monorepo and validation workflow

Priority: `P0`
Milestone: `A`
Depends on: none
Status: `Complete`

Scope:

- Create `apps/` and `packages/` workspace layout.
- Set up TypeScript project references, linting, formatting, tests, and publishable package builds.
- Add a shared validation workflow for install, build, lint, and test.

Acceptance criteria:

- The repo builds from a clean checkout.
- `apps/daemon` and `apps/cli` can import shared packages.
- Local validation commands cover install, build, typecheck, lint, and test checks.
- Lint and format commands are wired into the workspace and documented.

### CG-002 Define shared contracts and configuration schema

Priority: `P0`
Milestone: `A`
Depends on: `CG-001`
Status: `Complete`

Scope:

- Define scan, detonation, report, decision, artifact, IPC, and config types.
- Add runtime validation for persisted data and IPC payloads.
- Write ADRs for contracts, IPC versioning, and error taxonomy.

Acceptance criteria:

- All downstream packages can compile against `packages/contracts`.
- Invalid config and malformed IPC payloads fail fast.
- Example fixtures exist for the main contracts.
- ADRs exist for contracts, IPC versioning, storage strategy, and runtime-provider strategy.

### CG-003 Implement storage architecture

Priority: `P0`
Milestone: `A`
Depends on: `CG-001`, `CG-002`
Status: `Complete`

Scope:

- Create SQLite schema and migrations for structured state.
- Create artifact-store helpers for raw evidence files.
- Index artifacts from SQLite without storing large blobs in the database.

Acceptance criteria:

- A scan record can persist summary rows plus linked artifacts.
- Quarantine and allow or block decisions survive daemon restart.
- Artifact directories are deterministic and queryable from the DB.

### CG-004 Build platform interfaces and macOS adapters

Priority: `P0`
Milestone: `A`
Depends on: `CG-002`
Status: `Complete`

Scope:

- Define interfaces for filesystem watching, notifications, service install, and container runtime detection.
- Implement macOS adapters.
- Add Linux contract tests and placeholder stubs without shipping Linux behavior yet.

Acceptance criteria:

- macOS adapters satisfy all platform contracts.
- Core packages compile against interfaces, not direct macOS calls.
- Linux support can be added without changing scanner or daemon contracts.

## Epic B: Discovery and Interception

### CG-005 Implement OpenClaw workspace discovery

Priority: `P0`
Milestone: `A`
Depends on: `CG-002`, `CG-004`
Status: `Complete`

Scope:

- Parse `~/.openclaw/openclaw.json` as JSON5, including supported include chains, multi-agent workspaces, and extra skill directories.
- Discover workspace, managed, extra, lockfile, and fallback skill roots with stable precedence and deduplication.
- Probe the OpenClaw service separately to capture install/running signals and warnings without changing discovered paths.
- Normalize the result into an `OpenClawWorkspaceModel`.

Acceptance criteria:

- Discovery preserves the spec priority order for path sources.
- Missing config files and malformed lockfiles degrade cleanly.
- Service probe failures surface as warnings and do not break path discovery.
- Tests cover include handling, multi-agent configs, root deduplication, service-probe warnings, and fallback permutations.

### CG-006 Implement watcher pipeline and scan scheduling

Priority: `P0`
Milestone: `A`
Depends on: `CG-003`, `CG-004`, `CG-005`
Status: `Complete`

Scope:

- Watch all discovered skill roots on macOS, not a single canonical skills directory.
- Debounce and coalesce file events into one scan request per skill change.
- Preserve discovery metadata when emitting idempotent work items for the daemon.

Acceptance criteria:

- Repeated file writes do not create duplicate scans.
- New and modified skills are detected reliably across workspace, managed, extra, and fallback roots.
- Missing or temporarily absent roots do not crash watcher startup or recovery.
- The watcher can recover after transient filesystem errors.

### CG-007 Implement quarantine, allow, and block lifecycle

Priority: `P0`
Milestone: `A`
Depends on: `CG-003`, `CG-005`
Status: `Complete`

Scope:

- Rename suspicious skills into quarantine.
- Store allowlist and blocklist decisions by content hash.
- Restore or delete skills through explicit operator action.

Acceptance criteria:

- Quarantine is non-destructive and reversible.
- A hash-allowed skill bypasses repeat quarantine until content changes.
- A blocked hash is rejected on reappearance.

## Epic C: Static Scanner and Intelligence

### CG-008 Build skill snapshot and parser integration

Priority: `P0`
Milestone: `A`
Depends on: `CG-002`, `CG-005`
Status: `Complete`

Scope:

- Walk skills discovered from the normalized discovery model, hash contents, and inventory files.
- Parse `SKILL.md` and any available manifest data.
- Emit normalized `SkillSnapshot` objects for scanning, including discovery-derived source hints.

Acceptance criteria:

- The same skill contents always produce the same content hash.
- Snapshot output includes file inventory, parsed metadata, and discovery source context.
- Corrupt or partial skills return structured errors, not crashes.

### CG-009 Implement static rule engine and scoring

Priority: `P0`
Milestone: `A`
Depends on: `CG-008`
Status: `Complete`

Scope:

- Implement rules for exfiltration, prompt injection, memory tampering, privilege escalation, obfuscation, and staged download chains.
- Add rule metadata, severity, evidence capture, and explanation strings.
- Build the first risk score and quarantine recommendation model.

Acceptance criteria:

- Each finding includes rule ID, evidence, and human-readable reasoning.
- Staged-download fixtures are flagged by dedicated logic.
- Rule tests cover both malicious and benign examples.

### CG-010 Implement ClawHub API client

Priority: `P0`
Milestone: `A`
Depends on: `CG-002`
Status: `Complete`

Scope:

- Integrate `GET /api/v1/skills/{slug}`.
- Integrate `GET /api/v1/skills/{slug}/file?path=SKILL.md`.
- Integrate `GET /api/v1/skills?sort=trending|installs|recent`.
- Normalize any exposed ClawHub or VirusTotal verdict fields.

Acceptance criteria:

- The client can enrich a local scan with marketplace metadata.
- Remote `SKILL.md` retrieval works for slug-based audits.
- Missing verdict fields degrade to neutral rather than error.

### CG-011 Implement VirusTotal client, caching, and quota control

Priority: `P0`
Milestone: `A`
Depends on: `CG-002`, `CG-003`
Status: `Complete`

Scope:

- Integrate file-hash lookup via `GET /api/v3/files/{hash}`.
- Integrate async upload via `POST /api/v3/files` and `GET /api/v3/analyses/{id}`.
- Integrate URL, domain, and search endpoints for enrichment.
- Add caching, deduplication, and rate-budget enforcement.

Acceptance criteria:

- Hash lookups are usable on the blocking scan path.
- Uploads never block install-time decisions.
- Rate-limit exhaustion degrades cleanly and visibly.

### CG-012 Implement static report synthesis

Priority: `P0`
Milestone: `A`
Depends on: `CG-003`, `CG-009`, `CG-010`, `CG-011`
Status: `Complete`

Scope:

- Merge local findings, ClawHub metadata, and VirusTotal hash verdicts.
- Persist report summaries and artifact references.
- Render plain-language static reports for CLI and notifications.

Acceptance criteria:

- Reports explain why a skill was allowed or quarantined.
- ClawHub and VirusTotal signals appear as enrichment, not as sole verdicts.
- Stored reports can be loaded later by slug or hash.

## Epic D: Detonation Runtime

### CG-013 Build Podman runtime provider and sandbox image

Priority: `P1`
Milestone: `B`
Depends on: `CG-002`, `CG-004`
Status: `Complete`

Scope:

- Implement Podman runtime detection and command adapter.
- Build the base sandbox image and cache strategy.
- Add Docker provider parity through the same runtime contract.

Acceptance criteria:

- Podman is the default runtime when both are present.
- The sandbox image can be built or pulled repeatably.
- Docker compatibility passes the same contract tests.

### CG-014 Build dummy OpenClaw environment and honeypots

Priority: `P1`
Milestone: `B`
Depends on: `CG-013`
Status: `Complete`

Scope:

- Create a minimal agent environment inside the sandbox.
- Seed realistic decoy credentials and baseline memory files.
- Mount skill fixtures and workspace state consistently.

Acceptance criteria:

- Honeypot files are visible to detonated skills.
- Baseline memory files can be diffed after execution.
- The environment is deterministic enough for regression tests.

### CG-015 Implement prompt runner for staged-download workflows

Priority: `P1`
Milestone: `B`
Depends on: `CG-014`
Status: `Complete`

Scope:

- Execute 3 to 5 prompts that exercise declared skill capabilities.
- Follow setup, fetch, install, or initialization instructions called out in `SKILL.md`.
- Record tool-call intent and execution sequence.

Acceptance criteria:

- Workflow-malware fixtures trigger follow-on downloads or commands in the sandbox.
- Passive skills can still be detonated without false activation.
- Prompt execution is reproducible enough for test assertions.

### CG-016 Implement detonation telemetry capture and VT enrichment

Priority: `P1`
Milestone: `B`
Depends on: `CG-011`, `CG-014`, `CG-015`
Status: `Complete`

Scope:

- Capture process execution, network activity, file access, and memory diffs.
- Persist raw artifacts and normalized telemetry events.
- Enrich observed domains, URLs, IPs, and hashes through VirusTotal lookups.

Acceptance criteria:

- Reports can show what connected where and what files were touched.
- Network indicators can be enriched without blocking detonation completion.
- Raw artifacts are preserved for later review.

## Epic E: Daemon and CLI

### CG-017 Implement daemon job orchestration and IPC

Priority: `P0`
Milestone: `A`
Depends on: `CG-006`, `CG-007`, `CG-012`
Status: `Complete`

Scope:

- Build the daemon process, queue, retries, and backpressure rules.
- Expose a Unix socket API.
- Connect watcher-triggered scans to quarantine and report persistence.

Acceptance criteria:

- The daemon survives restart without losing persisted decisions.
- Concurrent scan requests are serialized or deduplicated safely.
- CLI clients can query daemon status and reports over IPC.

### CG-018 Implement CLI commands and output formatting

Priority: `P0`
Milestone: `A`
Depends on: `CG-007`, `CG-012`, `CG-017`
Status: `Complete`

Scope:

- Implement `report`, `allow`, `block`, `scan`, `status`, and `audit` end-to-end against daemon-backed state.
- Keep the `detonate` command on the CLI surface, but make its pre-Milestone-B behavior explicit and actionable.
- Format terminal output for both concise and detailed reports.
- Handle daemon-unavailable and runtime-unavailable cases cleanly.

Acceptance criteria:

- Static-path commands (`report`, `allow`, `block`, `scan`, `status`, and `audit`) work end-to-end against daemon-backed state.
- Operators can review and resolve quarantine decisions from the CLI.
- `detonate` returns a clear, actionable "not implemented yet" response until behavioral orchestration lands.
- Error messages are actionable and non-ambiguous.

### CG-019 Implement macOS notifications and launchd service setup

Priority: `P1`
Milestone: `C`
Depends on: `CG-004`, `CG-017`, `CG-018`
Status: `Complete`

Scope:

- Add notification delivery for quarantines and completed scans.
- Add `launchd` user-service install, status, and uninstall flows.
- Surface daemon health in the CLI.

Acceptance criteria:

- New quarantines generate a visible local notification.
- The daemon can be installed as a user service and restarted automatically.
- Service status is queryable from the CLI.

## Epic F: Quality, Benchmarks, and Launch

### CG-020 Build fixture corpus and benchmark harness

Priority: `P0`
Milestone: `A`
Depends on: `CG-001`
Status: `Complete`

Scope:

- Create benign and malicious skill fixtures.
- Include staged-download, memory-poisoning, and exfiltration examples.
- Add performance harnesses for static and detonation targets.

Acceptance criteria:

- Fixtures are reusable across unit, integration, and end-to-end tests.
- Static benchmark output is automated in a gated local workflow.
- Fixture coverage includes high-quality benign skills to track false positives.

### CG-021 Implement end-to-end regression and security validation

Priority: `P1`
Milestone: `B`
Depends on: `CG-016`, `CG-017`, `CG-018`, `CG-020`
Status: `Complete`

Scope:

- Add full pipeline tests from install detection to report generation.
- Validate quarantine safety, artifact integrity, and detonation containment assumptions.
- Track false-positive and latency regressions over time.

Acceptance criteria:

- The main static and detonation flows are covered end to end.
- Benchmark regressions are visible before release.
- Security validation results are recorded in repeatable test outputs.

### CG-022 Package release flow and launch docs

Priority: `P2`
Milestone: `C`
Depends on: `CG-018`, `CG-019`, `CG-021`
Status: `In Progress`

Scope:

- Finalize the single-package npm packaging, versioning, and tagged release automation path.
- Write operator docs, architecture docs, and security caveat docs.
- Prepare demo scenarios and launch assets.

Acceptance criteria:

- A release build can be installed and run from a clean machine.
- Docs clearly explain scope limits, Podman default, and VirusTotal caveats.
- Demo assets show both static detection and workflow-malware detonation.

## Recommended next ticket order

Immediate next tickets:

- `CG-022`

Current recommended parallel work:

- `CG-022` for packaging, operator docs, launch caveats, and release verification automation

Remaining Static MVP critical path:

- None (`CG-018` completed)

Behavioral MVP critical path:

- None (`CG-021` completed)

Tickets that should wait for dependencies to settle:

- None (`CG-019` landed)

Launch candidate closeout:

- `CG-022`
