# ADR 0001: Shared Contracts as the Single Source of Truth

- Status: Accepted
- Date: 2026-03-09

## Context

The monorepo scaffold established app and package boundaries in `cf2a349`, and `e9fd72c` introduced the real shared contract surface in `packages/contracts`. The CLI, daemon, storage layer, discovery package, and downstream scanner/reporting packages already import shared types from this package.

The repository also has a minimal but real error surface:

- `SchemaValidationError` for validator failures in `packages/contracts`
- structured daemon error envelopes in the IPC contracts
- typed platform errors for unsupported features and command execution failures

That error surface exists today, but the repository does not yet have a full cross-package error-code taxonomy.

## Decision

`packages/contracts` is the only source of truth for cross-package payloads, schemas, and runtime validators.

This means:

- shared domain, config, IPC, and example payload types live in `packages/contracts`
- runtime validators live beside the contract definitions they validate
- downstream packages compile against the shared contract package instead of redefining payload shapes locally
- the current minimal shared error approach is documented here rather than split into a standalone taxonomy ADR at this stage

## Consequences

- contract drift between apps and packages is reduced because shared payloads are defined once
- persisted data and IPC payloads can be validated consistently at the boundary
- new shared payloads must be added to `packages/contracts` before other packages depend on them
- a broader error taxonomy remains deferred until more subsystems share stable error categories and codes

## Alternatives Considered

- app-local or package-local copies of shared types, which would make drift and inconsistent validation much more likely
- moving shared schemas into a separate external schema tool or service, which would add dependency and workflow overhead without solving a current problem
- writing a standalone error-taxonomy ADR now, which would be premature given the current limited shared error surface
