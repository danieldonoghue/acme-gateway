# ADR 0007: Authoritative propagation quorum and dns-01 CNAME delegation

**Status:** Accepted — amended by [ADR 0008](0008-asynchronous-answer-challenge-processing.md)
**Date:** 2026-06-25

> **Amendment (ADR 0008):** The propagation check described here originally ran
> *synchronously* inside the answer-challenge request and *hard-failed* on
> timeout. As of ADR 0008 it runs in the background (answer-challenge returns
> immediately) and its timeout is *non-fatal* — on timeout the gateway triggers
> the upstream anyway. The `propagation` and `delegation` configuration below is
> unchanged; only the "requires quorum before proceeding" semantics are
> superseded.

## Context

Operational evidence with Anycast authoritative DNS showed transient divergence during zone publication:

- API accepted dns-01 TXT updates immediately.
- Different authoritative nodes converged at different times.
- During convergence, sequential lookups could return mixed results (TXT present, then NXDOMAIN).

For ACME dns-01, this creates intermittent validation failures when upstream validators query nodes that have not converged yet.

A second operational requirement is delegated challenge ownership:

- Some operators use `_acme-challenge.<domain> CNAME <delegated-name>`.
- TXT records must be written and verified at the delegated target name.

## Decision

acme-gateway adds two dns-01 policy controls under `dns_hook` (bootstrap and per-upstream):

1. `propagation` (authoritative quorum check)
- Before triggering the upstream challenge, the gateway polls authoritative nameservers for the target FQDN.
- It prefers quorum and stability (consecutive successes) before proceeding. (Per ADR 0008 this runs in the background and, on timeout, proceeds to trigger the upstream anyway rather than failing.)
- Default behavior is enabled with conservative values:
  - `timeout_seconds: 300`
  - `poll_seconds: 2`
  - `min_consecutive_successes: 3`
  - `quorum_percent: 100`

2. `delegation` (optional CNAME delegation)
- When enabled, the gateway resolves `_acme-challenge.<domain>` CNAME chains and uses the effective target FQDN for publish/check/cleanup.
- `mode` controls failure semantics:
  - `strict` (default): fail challenge preparation on delegation errors/policy violations.
  - `permissive`: fallback to source `_acme-challenge.<domain>`.
- `allowed_zone_suffixes` is optional:
  - If empty/unset, any delegated zone is accepted.
  - If set, effective targets must match one of the suffixes.

## Hook contract update

Hooks continue to receive legacy vars and now also receive source/effective target context:

- Legacy-compatible:
  - `CERTBOT_DOMAIN`, `CERTBOT_VALIDATION`, `CERTBOT_TOKEN`
  - `ACME_GATEWAY_DOMAIN`, `ACME_GATEWAY_FQDN`, `ACME_GATEWAY_DNS_VALUE`, `ACME_GATEWAY_TOKEN`
- New delegation-aware:
  - `CERTBOT_DOMAIN_SOURCE`, `CERTBOT_DOMAIN_EFFECTIVE`
  - `CERTBOT_FQDN_SOURCE`, `CERTBOT_FQDN_EFFECTIVE`
  - `ACME_GATEWAY_DOMAIN_SOURCE`, `ACME_GATEWAY_DOMAIN_EFFECTIVE`
  - `ACME_GATEWAY_FQDN_SOURCE`, `ACME_GATEWAY_FQDN_EFFECTIVE`

`CERTBOT_DOMAIN` / `ACME_GATEWAY_DOMAIN` now represent the effective target domain for dns-01 operations.

## Consequences

- Reduces transient dns-01 failures from authoritative convergence races.
- Supports delegated challenge ownership without changing ACME client behavior.
- Introduces extra pre-challenge latency when DNS is slow, traded for higher validation reliability.
- Allows optional policy hardening via suffix allow-lists; permissive mode remains available for migration.
