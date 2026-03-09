# ADR 0003: Hybrid Storage with SQLite and Flat-File Artifacts

- Status: Accepted
- Date: 2026-03-09

## Context

The product spec and `AGENTS.md` both call for hybrid persistence: structured/queryable state in SQLite and large or irregular evidence on disk. `791252f` implemented that approach in `packages/storage` using `node:sqlite`, migrations, artifact indexing, and config-driven path resolution.

The current storage layer already persists:

- scans, reports, decisions, quarantine records, and artifact indexes in SQLite
- evidence payloads through an artifact store on disk
- macOS default storage paths derived from the shared config

## Decision

ClawGuard uses hybrid persistence:

- SQLite for structured, queryable state
- flat files for large or evidence-heavy artifacts
- SQLite rows that index and reference the artifacts written to disk

The concrete implementation uses `node:sqlite` for the database layer and keeps the default macOS storage locations in shared config.

## Consequences

- queryable state remains simple to filter, join, deduplicate, and inspect
- large blobs stay out of the database and remain accessible as files
- Node 22 remains a hard platform requirement because the current storage implementation depends on `node:sqlite`
- the current experimental SQLite warning in Node is acceptable for now because it does not block the repository's existing runtime behavior

## Alternatives Considered

- storing all artifacts in SQLite blobs, which would make evidence-heavy storage less ergonomic and more expensive to manage
- storing all state in flat files, which would weaken queryability and historical inspection
- adopting an external database server or ORM, which would add operational overhead the current local-first product does not need
