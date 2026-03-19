# ClawGuard High-Level Implementation Plan

This plan translates the product spec in `docs/clawguard-spec-v2.docx` into a delivery structure that supports parallel development in a monorepo from day one. The core scope remains unchanged: ClawGuard decides whether a skill should be present on the machine, not whether a runtime tool call should execute.

## Current status snapshot

As of 2026-03-18, the repo has landed the foundational contracts and IPC shapes, the storage architecture, the macOS-first platform interfaces, the OpenClaw workspace discovery model, watcher scheduling, the quarantine lifecycle, skill snapshot production, the first static rule engine and scoring model, the ClawHub and VirusTotal client foundations, static report synthesis that merges local findings with enrichment signals (`CG-012`), the first Podman-first runtime provider with Docker-compatible sandbox-image preparation (`CG-013`), the first dummy OpenClaw detonation environment with honeypot scaffolding and smoke-run validation (`CG-014`), the staged-download prompt runner that executes reproducible prompt plans with setup-command sequencing and sandbox-side prompt execution (`CG-015`), syscall-traced detonation telemetry with preserved raw artifacts plus decoupled VirusTotal indicator enrichment (`CG-016`), daemon job orchestration plus Unix-socket IPC (`CG-017`), CLI command coverage with concise/detailed operator formatting and explicit pre-Milestone-B detonation messaging (`CG-018`), macOS notifications plus `launchd` user-service flows with daemon health surfacing (`CG-019`), the reusable fixture corpus plus gated static and full detonation benchmark harnesses (`CG-020`), the end-to-end regression/security validation layer covering watcher-driven static flow, restart persistence, detonation artifact integrity, and runtime-unavailable degradation (`CG-021`), and the `CG-022` packaging/versioning lane with a single installable root `clawguard` artifact, clean-machine tarball smoke validation, and tagged npm/GitHub release automation.

The main remaining work now centers on Milestone C launch hardening:

- release-facing docs completion, launch caveats, and demo assets (`CG-022`)

Recommended immediate execution focus:

- Finish the remaining `CG-022` docs, launch caveats, and demo collateral on top of the stabilized packaging, service, and notification flows.

## Confirmed architecture decisions

- Monorepo from day one.
- macOS-first MVP, with Linux added later through existing platform interfaces rather than a structural rewrite.
- Podman is the default detonation runtime. Docker remains a compatibility adapter, not the primary path.
- Hybrid persistence:
  - SQLite for structured state with stable schemas.
  - Flat files for large or irregular evidence artifacts.
- ClawHub and VirusTotal integrations are first-class parts of the scanner and reporting pipeline.

## Recommended monorepo layout

Use separate app entrypoints and reusable packages:

- `apps/daemon`: `clawguard daemon`
- `apps/cli`: `clawguard <command>`
- `packages/contracts`: shared TypeScript types and schemas
- `packages/platform`: OS and runtime interfaces plus macOS implementations
- `packages/storage`: SQLite repositories and artifact-store helpers
- `packages/discovery`: OpenClaw detection, workspace resolution, watcher pipeline
- `packages/integrations`: ClawHub and VirusTotal clients, caching, rate limiting
- `packages/scanner`: static analysis, rule engine, scoring
- `packages/detonation`: Podman/Docker orchestration, dummy agent, telemetry capture
- `packages/reports`: evidence normalization and plain-language output
- `packages/fixtures`: benign/malicious fixtures, benchmarks, regression corpus

This keeps the runtime apps thin and lets feature teams work mostly inside one package boundary at a time.

## Persistence strategy

Use a hybrid model rather than forcing everything into one store.

### SQLite for structured state

Store these in SQLite because the shape is known and queryability matters:

- skill inventory and scan history
- quarantine state
- allowlist and blocklist hashes
- rule findings and normalized report summaries
- daemon job state and timestamps
- API cache metadata and verdict summaries
- artifact indexes pointing to flat-file evidence locations

Recommended macOS location:

- `~/Library/Application Support/ClawGuard/state.db`

### Flat files for evidence artifacts

Store these as files because they are large, irregular, or append-only:

- raw `SKILL.md` snapshots
- full static analysis JSON output
- detonation stdout and stderr
- network captures and proxy logs
- file diffs and memory diffs
- rendered Markdown or JSON reports
- copied sandbox artifacts for forensic review

Recommended macOS location:

- `~/Library/Application Support/ClawGuard/artifacts/<scan-id>/`

### Storage rule of thumb

- If the system needs to filter, join, deduplicate, or show history over it, keep it in SQLite.
- If the payload is large, sparse, schema-fluid, or primarily for evidence review, keep it as a flat file and index it from SQLite.

## External intelligence integration strategy

The integrations should improve speed and explainability without becoming the primary detection engine.

### ClawHub integration

Implement support for:

- `GET /api/v1/skills/{slug}` for skill metadata and any exposed verdict fields
- `GET /api/v1/skills/{slug}/file?path=SKILL.md` for remote `SKILL.md` retrieval
- `GET /api/v1/skills?sort=trending|installs|recent` for audit and benchmark corpus seeding

Use ClawHub for:

- skill metadata enrichment in reports
- passthrough of existing ClawHub or VirusTotal verdicts if exposed in the payload
- remote fetch of marketplace `SKILL.md` when auditing a slug without a local install

Do not treat a missing or clean ClawHub verdict as proof of safety.

### VirusTotal integration

Implement support for:

- `GET /api/v3/files/{hash}` for synchronous hash lookups during the static path
- `POST /api/v3/files` plus `GET /api/v3/analyses/{id}` for asynchronous uploads of unknown, high-risk samples
- `POST /api/v3/urls` and `GET /api/v3/domains/{domain}` for network enrichment after detonation
- `GET /api/v3/search?query={indicator}` for ad hoc enrichment of hashes, IPs, URLs, and domains

Use VirusTotal for:

- fast known-bad lookup by content hash
- enrichment of domains, URLs, and IPs observed in detonation
- optional background submission of suspicious unknown samples

Do not use VirusTotal file upload as part of the blocking install path. It is too rate-limited and too slow for the `<2s` target. Uploads should be asynchronous, cached, and quota-aware.

### Integration policy

- Hash lookup is inline on the static scan path.
- Upload is background-only or explicitly requested by the operator.
- Domain and URL checks happen after detonation telemetry is available.
- All external calls are wrapped in a cache and quota governor.
- VirusTotal results are always presented as one signal, not the final verdict.

## Shared contracts to lock first

Before multiple developers fan out, define these contracts in `packages/contracts`:

- `SkillSnapshot`: local path, slug, source hints, file inventory, content hashes, parsed metadata
- `StaticFinding` and `StaticScanReport`: rule IDs, severity, evidence, score, recommendation
- `ThreatIntelVerdict`: provider, object type, verdict summary, engine counts, confidence, cache metadata
- `DetonationRequest` and `DetonationReport`: prompt set, runtime, tool calls, network events, file diffs, summary
- `DecisionRecord`: quarantine state, allow or block action, hash status, timestamps
- `ArtifactRef`: artifact type, on-disk path, MIME type, owning scan ID
- `PlatformCapabilities`: watcher, notifications, service install, runtime availability
- `OpenClawWorkspaceModel`: config path, primary workspace, deduplicated skill roots, service signals, warnings
- `DaemonEvent`: scan requested, scan completed, detonation completed, quarantine changed, notification sent

Once these contracts are stable, the streams below can move in parallel with low coordination cost.

## Workstreams

### 1. Monorepo Foundation and Contracts

Scope:

- Initialize the monorepo, package tooling, linting, testing, builds, and release flow.
- Define the shared contracts, configuration model, logging conventions, and error taxonomy.
- Establish app and package boundaries so downstream work does not collapse into one package.

Current status:

- Monorepo package boundaries, builds, typechecks, tests, lint/format tooling, and ADRs are in place.

Outputs:

- Working monorepo scaffold.
- Shared contracts package consumed by all apps and packages.
- ADRs for layout, IPC, storage, and runtime-provider strategy.

Dependencies:

- None.

### 2. Storage and Platform Abstractions

Scope:

- Implement SQLite repositories and artifact-store helpers.
- Define platform interfaces for watchers, notifications, service lifecycle, runtime detection, and filesystem primitives.
- Provide macOS implementations first, with Linux interface shims and contract tests in place.

Outputs:

- Stable storage layer using SQLite plus artifact paths.
- Platform abstraction package with macOS adapters.
- Testable seam for future Linux support.

Dependencies:

- Workstream 1.

### 3. OpenClaw Discovery, Watcher, and Quarantine

Scope:

- Detect OpenClaw workspaces and skill roots from JSON5 config, lock files, managed defaults, extra directories, and known fallback locations.
- Record OpenClaw service install/running state as an auxiliary signal without affecting path precedence.
- Implement macOS watcher integration with debouncing and idempotent scan scheduling across all discovered skill roots.
- Create quarantine, allow, and block flows using content hashes and non-destructive rename semantics.

Outputs:

- Discovery module that returns the normalized `OpenClawWorkspaceModel`.
- Watcher pipeline that schedules skill work from all discovered skill roots.
- Snapshot builder that emits `SkillSnapshot` objects with discovery-derived source hints.
- Quarantine lifecycle backed by SQLite state and artifact references.

Dependencies:

- Workstreams 1 and 2.

### 4. Static Analysis and Threat Intelligence

Scope:

- Parse skill metadata and contents, including `SKILL.md`.
- Implement rules for exfiltration, prompt injection, memory tampering, privilege escalation, obfuscation, and staged download chains.
- Build ClawHub and VirusTotal clients, caching, and rate limiting.
- Produce a deterministic score and explanation model for inline decisions.

Outputs:

- Static scanner returning `StaticScanReport`.
- ClawHub client for metadata and remote `SKILL.md` retrieval.
- VirusTotal client for file-hash, URL, domain, and background upload flows.

Dependencies:

- Workstreams 1 and 2.
- Workstream 9 fixtures are helpful but not blocking.

### 5. Podman-First Detonation Runtime

Scope:

- Build the sandbox runtime around Podman first, with Docker as a secondary adapter.
- Create a dummy OpenClaw environment with realistic honeypots and baseline memory files.
- Follow skill setup and install instructions during prompt execution so workflow malware actually triggers.
- Capture process execution, network traffic, file access, and memory changes.

Outputs:

- Podman runtime provider and sandbox image.
- Docker compatibility provider using the same contract surface.
- Raw detonation telemetry and artifact capture.

Dependencies:

- Workstreams 1 and 2.

### 6. Evidence Synthesis and Reporting

Scope:

- Merge static findings, threat-intel verdicts, and detonation evidence into one report model.
- Persist report summaries in SQLite and full evidence in artifacts.
- Generate plain-language summaries suitable for terminal output and notifications.

Outputs:

- Shared reporting library.
- Unified risk synthesis model.
- Report persistence and retrieval layer.

Dependencies:

- Workstreams 2, 4, and 5.

### 7. Daemon Orchestration and IPC

Scope:

- Implement the long-running daemon, job queue, scan pipeline, retries, and backpressure.
- Expose a Unix socket API for the CLI.
- Connect watcher events to static scan, optional detonation, quarantine changes, and notifications.

Outputs:

- `clawguard daemon`
- IPC protocol and handlers
- End-to-end install interception pipeline

Dependencies:

- Workstreams 3, 4, and 6.

### 8. CLI, Notifications, and macOS Service Install

Scope:

- Build `report`, `allow`, `block`, `scan`, `detonate`, `status`, and `audit`.
- Implement terminal formatting, failure handling, and daemon fallback behavior.
- Add macOS notifications and `launchd` user-service installation.

Outputs:

- Full CLI surface for MVP.
- Operator-facing notifications.
- macOS service install flow.

Dependencies:

- Workstreams 2, 6, and 7.

### 9. Fixtures, Benchmarks, and Launch Readiness

Scope:

- Create benign and malicious fixture skills, including staged-download samples.
- Build benchmark harnesses for the `<2s` static target and `<90s` detonation target.
- Add regression, integration, and end-to-end coverage.
- Produce onboarding docs, architecture docs, and launch assets.

Outputs:

- Shared fixture corpus.
- Benchmark and regression gates in local validation workflows.
- Launch-ready docs with honest security caveats.

Dependencies:

- Starts early and expands as other workstreams land.

## Recommended execution order

### Wave 0

- Start Workstream 1 immediately.
- Start Workstream 9 fixture creation in parallel.
- Lock contracts, storage policy, and platform interfaces before feature work spreads.

### Wave 1

- Run Workstream 2 and Workstream 3 in parallel.
- Start Workstream 4 once contracts and storage are stable enough for scanner outputs.
- Start Workstream 8 against mocked daemon responses so CLI UX is not blocked.

### Wave 2

- Build Workstream 5 as a standalone detonation runner.
- Connect Workstream 6 to static results first, then add detonation evidence.
- Land Workstream 7 to orchestrate watcher to scan to quarantine to report.

### Wave 3

- Integrate the real CLI with daemon IPC.
- Add ClawHub and VirusTotal enrichment to both static reports and detonation summaries.
- Harden Podman-first detonation on realistic fixtures.

### Wave 4

- Validate performance targets.
- Finish macOS service install and onboarding.
- Tighten docs around sandbox limitations, quota caveats, and scope boundaries.

## Milestones

### Milestone A: Static MVP

Goal:

- Intercept local installs, run static scan, enrich from ClawHub and VirusTotal hash lookup, quarantine when needed, and expose operator decisions through the CLI.

Primary workstreams:

- 1, 2, 3, 4, 6, 7, 8, 9

Exit criteria:

- Suspicious skills are intercepted before the next OpenClaw session.
- Static scan plus threat-intel lookup is explainable and persisted.
- The static blocking path is near or under the 2-second target.

### Milestone B: Behavioral MVP

Goal:

- Add Podman-based detonation, realistic staged-download execution, network and file telemetry, and unified behavioral reporting.

Primary workstreams:

- 5, 6, 7, 8, 9

Exit criteria:

- Workflow-malware fixtures trigger follow-on execution in the sandbox.
- Reports show what was fetched, executed, touched, and where it connected.
- Warm-cache detonation is near or under the 90-second target.

### Milestone C: Launch Candidate

Goal:

- Deliver packaging, service install, benchmarks, docs, and a stable operator experience on macOS.

Primary workstreams:

- 8 and 9, plus stabilization across all prior workstreams

Exit criteria:

- Fresh install leads to a running daemon with minimal manual setup.
- CLI and daemon behavior are stable on macOS.
- Linux support can be added by implementing the platform contracts, not by restructuring the codebase.

## Cross-team handoff rules

- `packages/contracts` is the only source of truth for scanner, detonation, IPC, and reporting payloads.
- `packages/storage` owns persistence primitives. Other packages should not invent their own state stores.
- `packages/platform` owns OS-specific behavior. Other packages should code against interfaces only.
- Every score-affecting finding must carry machine-readable evidence and a human-readable explanation.
- Every artifact written to disk must have a corresponding `ArtifactRef` so reports remain navigable.

## Suggested team split

If you have 4 to 6 engineers, this split is efficient:

- Engineer 1: Workstream 1 plus architecture support
- Engineer 2: Workstreams 2 and 3
- Engineer 3: Workstream 4 and external integrations
- Engineer 4: Workstream 5
- Engineer 5: Workstreams 6 and 8
- Engineer 6: Workstreams 7 and 9

## Risks to track from day one

- Sandbox realism: detonation only matters if staged-download workflows actually execute.
- Rate limits: VirusTotal free-tier limits require caching, coalescing, and asynchronous uploads.
- False positives: scoring must stay conservative and explainable.
- Event storms: watcher and daemon need debouncing and idempotency.
- Scope creep: do not drift into runtime tool-call mediation.
