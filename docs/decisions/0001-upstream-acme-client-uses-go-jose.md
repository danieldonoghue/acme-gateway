# ADR 0001: Upstream ACME client uses go-jose directly, not `x/crypto/acme`

**Status:** Accepted
**Date:** 2026-05-21

## Context

The gateway acts as an ACME client to upstream CAs (Let's Encrypt, private CA
instances, etc.). The natural choice would be `golang.org/x/crypto/acme`, which
provides a high-level ACMEv2 client.

The original build specification (§12) listed `x/crypto/acme` as the intended
upstream client. The implementation departs from this and uses `github.com/go-jose/go-jose/v4`
directly to JWS-sign upstream requests, with a thin HTTP layer for nonce
management and directory caching ([internal/upstream/client.go](../../internal/upstream/client.go)).

## Decision

Build the upstream ACME client on go-jose, not `x/crypto/acme`.

## Rationale

The gateway has requirements that don't sit cleanly on top of `x/crypto/acme`:

- **Per-rule control over the `profile` field on `newOrder`.** The strip / override /
  passthrough behaviour ([internal/router/router.go](../../internal/router/router.go))
  needs to decide at request-construction time whether to include the `profile`
  field at all, what value to send, and whether to forward the inbound value
  verbatim. `x/crypto/acme` doesn't expose the request body construction at that
  level of granularity.
- **EAB per upstream account.** Each upstream gets its own gateway-owned keypair
  and its own EAB credential set. The EAB JWS payload is the gateway's public JWK,
  signed with the CA-operator-provided HMAC. Doing this through `x/crypto/acme`
  means working around its account-creation flow rather than with it.
- **Direct visibility into JWS framing.** The gateway re-originates traffic, so
  bugs in upstream JWS construction surface as opaque CA-side rejections. Owning
  the framing makes them debuggable in our own code.

## Consequences

### Accepted

We re-implement ACME-client edge cases that `x/crypto/acme` would have handled:

- **`badNonce` retry.** A `badNonce` response from the upstream needs a nonce
  refresh and a retry. Currently the client refreshes via `saveNonce` from the
  response header and surfaces the error to the caller; there is no automatic
  retry loop. Callers that hit this will see a transient failure.
- **EAB HMAC key encoding.** RFC 8555 §7.3.4 says the EAB HMAC key is
  base64url-encoded, but several CAs in the wild distribute it with standard
  base64 padding. The client tries raw-URL first and falls back to standard
  ([internal/upstream/account.go:76-83](../../internal/upstream/account.go#L76)).
  New CAs may surface new variants.
- **POST-as-GET.** Implemented as `signedPost(ctx, url, nil)` ([internal/upstream/client.go:271-273](../../internal/upstream/client.go#L271)).
  Easy to forget if a new endpoint is added — there's no type-level enforcement.
- **Algorithm support.** Currently ECDSA P-256 only for upstream signing. RFC
  8555 permits RSA and Ed25519; if a future upstream requires one of these the
  signer construction needs to broaden.
- **Retry-After honouring on poll endpoints.** Not currently implemented; we
  poll on a fixed 5-second interval ([internal/bootstrap/bootstrap.go:316-330](../../internal/bootstrap/bootstrap.go#L316)).
  A CA that emits `Retry-After` to throttle clients won't be respected.

### Rejected alternatives

- **Use `x/crypto/acme` and patch around the profile-field gap.** Would mean
  either forking the package or constructing the order request body twice (once
  via the high-level API, once raw) — both worse than just owning the client.
- **Mix: use `x/crypto/acme` for account/nonce management, hand-roll order
  submission.** Splits the nonce pool across two clients and doubles the
  surface area.

## Review trigger

Revisit this decision if:

- We hit two or more upstream-interop bugs traceable to JWS framing or nonce
  handling that `x/crypto/acme` would have caught.
- The ACME spec extends in a way (new request types, mandatory algorithm
  changes) that `x/crypto/acme` adopts and we'd otherwise have to chase.
- We need to support a new key type for upstream signing.
