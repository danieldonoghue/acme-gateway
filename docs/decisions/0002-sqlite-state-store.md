# ADR 0002: SQLite as the state store

**Status:** Accepted  
**Date:** 2026-05-21

## Context

The gateway needs to persist ACME state across restarts: gateway client accounts,
upstream CA accounts and keypairs, in-flight orders, resource mappings (order/authz/
challenge/cert UUID → upstream URL), and single-use replay-protection nonces.

The deployment target is a single binary on a Linux server or in a distroless
container. The anticipated write rate is low: a burst of N simultaneous renewals
each generates roughly 5–8 writes (order + authz resources + nonce consumption),
spread over the 3–5 minute duration of the ACME challenge flow.

## Decision

Use SQLite (via `modernc.org/sqlite`, a pure-Go port) as the sole state store.

## Rationale

- **Zero operational overhead.** No separate database process, connection string,
  credentials, or network dependency. The binary plus a single `.db` file is a
  complete deployment.
- **WAL mode + `busy_timeout` cover the concurrency profile.** WAL allows
  concurrent reads. Writes serialise at the SQLite level, which is fine because
  the expected peak write rate (even at 100 simultaneous renewals) is on the order
  of tens of writes per second — well within SQLite's capability on any modern disk.
  `PRAGMA busy_timeout=5000` gives writers a 5-second retry window rather than
  failing immediately on lock contention.
- **The workload is not relational at scale.** All queries are primary-key or
  indexed lookups; there are no cross-account joins or aggregations that would
  benefit from a full RDBMS.
- **Schema migrations are simple.** `CREATE TABLE IF NOT EXISTS` plus idempotent
  `ALTER TABLE … ADD COLUMN` (SQLite silently errors on duplicate columns, which
  the migration code ignores) keeps upgrades seamless.

## Known ceiling

At significantly higher load — hundreds of concurrent renewing clients — SQLite's
single-writer constraint could become a throughput bottleneck. The `Store` type
exposes a narrow interface (all persistence behind method calls on `*Store`), so
swapping to PostgreSQL or MySQL would require only new implementations of the store
methods and a migration of the schema; no handler or pool logic would need to change.

## Consequences

- The `.db` file must reside on a filesystem that supports `fcntl` byte-range
  locking (NFS and some network filesystems do not). The service unit and Helm
  chart both write to a local volume for this reason.
- SQLite WAL mode leaves a `-wal` and `-shm` sidecar file alongside the database.
  These are part of the live database and must not be deleted while the gateway is
  running.
- `modernc.org/sqlite` adds ~6 MB to the binary but removes the CGO dependency,
  keeping cross-compilation (`GOOS=linux GOARCH=arm64`) trivial from any host.
