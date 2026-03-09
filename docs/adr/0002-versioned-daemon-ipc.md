# ADR 0002: Versioned Daemon IPC with Runtime Validation

- Status: Accepted
- Date: 2026-03-09

## Context

ClawGuard is split into a CLI and a long-running daemon. `e9fd72c` introduced the IPC contract in `packages/contracts/src/ipc.ts`, added runtime validators for the request and response envelopes, and documented the human-readable overview in `docs/ipc-overview.md`.

The current codebase already assumes:

- local process-to-process communication between the CLI and daemon
- a small, explicit command surface
- structured success and error envelopes
- versioned envelopes rather than ad hoc JSON blobs

## Decision

ClawGuard uses versioned daemon IPC envelopes with runtime validation at the boundary.

The protocol shape is:

- a top-level `DaemonRequestEnvelope` with `version`, `requestId`, and a command payload
- a top-level `DaemonResponseEnvelope` with `version`, `requestId`, and either structured success data or a structured error
- runtime validation for inbound and outbound payloads using the contract validators

The exact field-level shapes are documented in `docs/ipc-overview.md`; this ADR records the architectural choice, not a duplicate of the full schema.

## Consequences

- IPC evolution can happen through explicit versioning instead of silent wire-shape changes
- request and response validation failures can fail fast at the boundary
- the CLI stays decoupled from daemon internals and talks through a narrow, explicit interface
- future transport changes can preserve the same envelope model if the socket implementation changes

## Alternatives Considered

- unversioned JSON payloads, which would make compatibility drift harder to control
- direct shared-library calls from the CLI into daemon internals, which would collapse the process boundary
- per-command transport conventions without a shared envelope, which would make validation and compatibility more error-prone
