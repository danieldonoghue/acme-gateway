# ADR 0003: No live-reload for externally-managed TLS certificates

**Status:** Accepted  
**Date:** 2026-05-21

## Context

The gateway supports two certificate provisioning modes:

1. **Bootstrap-managed** (`bootstrap.enabled: true`): the gateway obtains and
   auto-renews its own TLS certificate via ACME. Renewal triggers a hot swap
   through `server.SetCertificate`, so the process never needs to restart.

2. **Externally-managed** (`bootstrap.enabled: false`): the operator supplies
   `cert_path` and `key_path`. An external agent (cert-manager, Ansible, manual)
   is responsible for renewal. The gateway loads the keypair once at startup.

The question is whether the external-cert path should also support live reload
(picking up a new file on disk without a process restart), most commonly via a
`SIGHUP` signal or a background file-watcher.

## Decision

No live-reload for the external-cert path. A process restart is required after
certificate renewal.

## Rationale

- **Operational simplicity.** A restart is the conventional and well-understood
  mechanism. Every supervisor (systemd, Docker, Kubernetes) handles it natively.
  Operators already write post-renewal restart hooks for other services; the
  same pattern applies here.

- **Auditability.** A restart produces a clear event in process supervision logs
  and leaves an unambiguous entry in systemd journal / container log streams. A
  silent in-process reload is harder to observe and confirm.

- **Low cost of restart.** The gateway is stateless across requests (all durable
  state lives in SQLite). A restart under systemd takes under a second and causes
  no data loss. The operational overhead is negligible.

- **Asymmetry is acceptable.** The bootstrap-managed path uses `SetCertificate`
  because there is no other way — the process itself obtained the certificate and
  is the only thing holding it in memory. The external path has no such constraint.

- **SIGHUP complexity.** Implementing `SIGHUP`-based reload requires careful
  synchronisation with in-flight TLS handshakes, error handling for a bad new
  cert (should the old cert stay in service?), and test coverage. The benefit
  does not justify the complexity at this stage.

## Alternatives considered

| Alternative | Reason not chosen |
|---|---|
| `SIGHUP` handler calling `tls.LoadX509KeyPair` + `SetCertificate` | Adds complexity; restart is sufficient |
| Periodic stat-and-reload background goroutine | Implicit, hard to observe, adds goroutine leak risk |
| inotify / fsnotify file watcher | External dependency; same observability concern as periodic poll |

## Consequences

- Operators using the external-cert path must include a gateway restart in their
  renewal post-hook. The example systemd unit and config documentation reflect this.
- If a future use case makes restart genuinely unacceptable (e.g. long-lived TLS
  connections, very high connection rate), this decision should be revisited.
  The `SetCertificate` plumbing already exists; adding `SIGHUP` handling would
  be a self-contained change.
