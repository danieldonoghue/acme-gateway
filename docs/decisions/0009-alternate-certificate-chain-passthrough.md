# ADR 0009: Pass through upstream alternate certificate chains

**Status:** Accepted
**Date:** 2026-07-02

## Context

Some ACME clients support selecting a preferred certificate chain (for example,
Certbot's preferred-chain behavior). In ACME, chain selection happens at
certificate download time:

1. Client polls order until `certificate` URL is available.
2. Client fetches the certificate URL (POST-as-GET).
3. CA may return `Link: <...>; rel="alternate"` headers for alternate chains.
4. Client may fetch one of those alternate URLs and choose the chain it wants.

Before this decision, acme-gateway proxied only a single certificate body and
did not expose upstream alternate `Link` metadata. As a result, clients behind
the gateway could not discover or retrieve alternate chains through gateway URLs.

## Decision

acme-gateway will transparently pass through upstream alternate certificate chain
metadata and retrieval paths.

Specifically:

- When fetching an upstream certificate URL, parse `Link` headers with
  `rel="alternate"`.
- For each alternate upstream certificate URL, create/resolve a gateway cert
  resource mapping.
- Return downstream `Link` headers with `rel="alternate"` that point to
  gateway `/cert/{id}` URLs.
- Keep default certificate body behavior unchanged.

No operator configuration knob is required for this capability. Chain policy
remains client-driven.

## Rationale

- Preserves ACME transparency: clients continue to use standard ACME semantics.
- Avoids introducing gateway policy that could conflict with client intent.
- Keeps chain choice where the ecosystem expects it: at client certificate
  retrieval.
- Fits existing resource-map architecture (certificate URL rewriting).

## Consequences

- Clients that support alternate chain selection can now function through the
  gateway without protocol changes.
- The gateway remains neutral: it exposes alternatives but does not force one.
- If an upstream CA does not advertise alternates, behavior is unchanged.

## Alternatives considered

| Alternative | Reason not chosen |
|---|---|
| Add `upstream_chain_pref` config and force a chain in the gateway | Introduces server-side policy for a problem clients already solve; less transparent |
| Keep current single-chain proxy behavior | Prevents preferred-chain capable clients from working as intended behind the gateway |

## Review trigger

Revisit this decision if:

- Multiple clients require server-side chain policy enforcement independent of
  client behavior.
- Upstream CAs deprecate `Link rel="alternate"` semantics in favor of another
  mechanism.
