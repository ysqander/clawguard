# ADR 0004: macOS-First Platform Abstraction and Podman-First Runtime Providers

- Status: Accepted
- Date: 2026-03-09

## Context

The product is macOS-first for the MVP, with Linux support planned later through platform contracts rather than a repo restructure. `900a0cd` implemented the core platform abstraction package, macOS adapters, Linux placeholders, and container runtime detection. The repository-level operating rules in `AGENTS.md` also fix Podman as the default detonation runtime and Docker as a compatibility path.

The current codebase already centralizes:

- platform capability reporting
- watcher, notification, and service-manager interfaces
- runtime detection for Podman and Docker
- platform adapter creation behind a single factory

## Decision

ClawGuard keeps all OS-specific behavior behind `packages/platform` and treats Podman as the default detonation runtime provider.

This means:

- apps and higher-level packages depend on platform interfaces, not raw `process.platform` branches spread across the codebase
- macOS gets the first concrete adapters for watcher, notifications, and service management
- Linux support is added later by implementing the existing contracts
- Podman is preferred when both Podman and Docker are available, while Docker remains a compatibility adapter through the same runtime contract surface

## Consequences

- platform-specific logic stays isolated and easier to extend without architectural churn
- macOS can move ahead without blocking on Linux feature parity
- detonation runtime selection remains explicit and testable
- Docker support remains available without flipping the repo's Podman-first design assumption

## Alternatives Considered

- scattering platform checks across apps and packages, which would make later Linux support harder to contain
- restructuring the repo around Linux support before the interfaces are proven, which would add complexity too early
- making Docker the default runtime, which would conflict with the current product and repository decisions
