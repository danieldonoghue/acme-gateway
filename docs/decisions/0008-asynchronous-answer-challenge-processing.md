# ADR 0008: Asynchronous answer-challenge processing and best-effort propagation

**Status:** Accepted
**Date:** 2026-06-26
**Amends:** [ADR 0007](0007-authoritative-propagation-and-dns01-delegation.md)

## Context

ADR 0007 introduced an authoritative propagation quorum gate that ran **before
triggering** the upstream dns-01 challenge. In the original implementation this
work was performed **synchronously inside the ACME answer-challenge request**
(`POST /challenge/{id}`): the handler ran the deploy hook, polled authoritative
nameservers until quorum, triggered the upstream challenge, and only then wrote
the HTTP response.

Two problems surfaced in production behind a Kubernetes ingress / service mesh:

1. **Reverse-proxy and client read timeouts.** Answer-challenge is supposed to
   return quickly (RFC 8555 §7.1.6: the challenge transitions to `processing`
   and validation proceeds asynchronously while the client polls the
   authorization). Blocking the response for the duration of DNS propagation
   meant an Envoy route timeout (default 15s) returned `504 upstream request
   timeout` to the client long before propagation completed. The certificate
   request aborted even though DNS and the upstream were healthy.

2. **Quorum gate could never be satisfied.** With anycast authoritative DNS
   whose nodes converge at different times (the motivating case in ADR 0007),
   the default `quorum_percent: 100` can stall against a single chronically
   lagging node. Combined with a synchronous, hard-failing gate, this turned a
   transient convergence race into a hard failure.

## Decision

### 1. Answer-challenge is non-blocking

`POST /challenge/{id}` validates the request, then starts the deploy →
propagation → upstream-trigger workflow in a **background goroutine** and
returns immediately with the challenge in `processing`. The parent
authorization (polled by the ACME client) reflects the live upstream status
once the trigger completes, so no client-visible behavior is lost.

Processing is idempotent: a retried answer for the same challenge does not
re-deploy or re-trigger. A gateway-side failure that occurs *before* the
upstream is triggered (e.g. a deploy-hook error) is surfaced as an `invalid`
challenge/authorization on the next poll, so clients fail fast instead of
polling a `pending` authorization until their own deadline.

### 2. Propagation is best-effort, not a hard gate

The propagation wait is retained but its **timeout is non-fatal**. Because the
TXT record has already been published by the deploy hook, on a quorum timeout
the gateway logs a warning and **triggers the upstream anyway**, letting the CA
perform validation against whichever authoritative nodes have converged. This
matches real anycast behavior, where a validator is likely to hit a converged
node even when 100% local quorum is never observed.

A deploy-hook **error** (the record was never published) remains fatal and
fails the challenge — there is nothing for the CA to validate.

This supersedes ADR 0007's statement that the gateway "requires quorum and
stability before proceeding." It now *prefers* quorum and proceeds on timeout.

## Consequences

- Answer-challenge latency is bounded and small; the gateway no longer depends
  on reverse-proxy or client read-timeout tuning to issue dns-01 certificates.
- Propagation latency moves off the request path into background processing;
  the client observes it as time-in-`pending` while polling, not as a hung POST.
- `quorum_percent: 100` against a chronically lagging authoritative node no
  longer hard-fails issuance. It does, however, make the background worker wait
  the full `timeout_seconds` before triggering. Operators of such CAs should set
  `quorum_percent` below 100 (e.g. 80 for a 4-of-5 anycast set) and/or a shorter
  `timeout_seconds` to minimize the pre-trigger delay. The propagation defaults
  are unchanged.
- Gateway-side pre-trigger failures are tracked in memory keyed by challenge ID
  to keep answer-challenge idempotent and to surface failures on the authz poll.

## Alternatives considered

| Alternative | Reason not chosen |
|---|---|
| Keep synchronous; document a required proxy timeout bump | Fragile — every proxy, mesh, and ACME client in the path would need tuning; still races against client socket timeouts. |
| Hard-fail on propagation timeout (keep ADR 0007 semantics) | Against an authoritative set that never reaches the configured quorum it can never succeed; the published record is usually validatable regardless. |
| Persist challenge processing state in the store | Unnecessary: processing is short-lived and tied to a single in-flight order; in-memory tracking is sufficient and avoids schema/migration churn. |
