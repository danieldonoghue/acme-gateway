# ADR 0004: Bind upstream ACME accounts to gateway client accounts for new orders

**Status:** Accepted  
**Date:** 2026-06-23

## Context

The gateway proxies ACME requests to upstream CAs and rewrites resource URLs
between gateway UUIDs and upstream URLs.

For `dns-01`, RFC 8555 requires the challenge TXT value to be derived from the
key authorization, where key authorization depends on the account key used for
the challenge context.

Historically, the gateway created upstream orders using round-robin pooled
upstream accounts keyed by `(upstream_id, slot)`. This caused a mismatch for
strict upstreams (notably Let's Encrypt):

- Client publishes TXT derived from the client-side account context.
- Upstream validates against the account context tied to the upstream order.
- If those account contexts diverge, validation fails immediately with
  `status=invalid` even when DNS propagation is correct.

Private CA profiles in local testing did not expose this gap because validation
semantics were less strict or challenge behavior differed.

## Decision

For new orders, bind upstream account usage to the gateway account creating the
order, not to round-robin pool slots.

Implementation details:

- Add per-account upstream account persistence keyed by
  `(upstream_id, account_id)` in `upstream_accounts_by_account`.
- Add pool lookup/creation API for account-bound clients.
- Route `new-order` through account-bound upstream clients.
- Preserve compatibility for existing orders created under slot routing.

Compatibility contract:

- Legacy orders continue to use slot-based routing (`upstream_slot >= 0`).
- New account-bound orders use sentinel `upstream_slot = -1` and resolve client
  by `(upstream_id, account_id)`.

## Rationale

- **RFC-aligned behavior for strict CAs.** Avoids challenge/account context drift
  introduced by cross-account order creation.
- **Deterministic routing.** Every gateway account consistently maps to the same
  upstream account per upstream CA.
- **Backward compatibility.** Existing in-flight and historical orders remain
  resolvable without migration of old rows.
- **Operational safety.** No destructive schema rewrite required; additive table
  plus dual-resolution logic is low risk.

## Alternatives considered

| Alternative | Reason not chosen |
|---|---|
| Keep slot-only pool and increase DNS wait/retry | Does not fix account-context mismatch; only masks timing |
| Gateway protocol extension to return upstream-derived TXT value | Non-standard ACME behavior; requires client changes |
| Bypass gateway for challenge validation with direct LE interaction | Architecturally invasive and breaks gateway ownership model |
| Full immediate migration of all historical orders/accounts | Unnecessary risk; dual-mode compatibility is sufficient |

## Consequences

- Upstream account cardinality grows with active gateway account count per
  upstream (instead of fixed `account_count` slots for new orders).
- New orders against strict upstreams are no longer impacted by pooled-slot
  account mismatch.
- Slot pool remains available for legacy order operations and fallback paths.
- Revocation and other order-bound operations must resolve client via
  dual strategy (slot for legacy, account binding for new).

## Follow-up

- Consider deprecating slot-based new-order routing after legacy data naturally
  ages out.
- Add explicit metrics for account-bound upstream account creation and cache hit
  rate.
- Reassess whether `account_count` should remain configurable for strict CAs or
  be treated as legacy-only behavior.
