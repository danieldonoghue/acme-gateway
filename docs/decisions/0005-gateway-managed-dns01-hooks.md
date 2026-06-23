# ADR 0005: Gateway-managed DNS-01 TXT publication via operator hooks

**Status:** Accepted  
**Date:** 2026-06-23

## Context

Following ADR 0004's account-bound upstream routing, the gateway routes each client order to a dedicated upstream ACME account. For dns-01 challenges, RFC 8555 specifies that the validation TXT value must be derived from the account's key authorization:

```
key_auth = token + "." + base64url(sha256(JWK_thumbprint))
TXT_value = base64url(sha256(key_auth))
```

In a proxy architecture:
- **Client-side TXT** = derived from the client's gateway-side account key
- **Upstream-side TXT** = derived from the gateway's upstream account key

These are different values. The upstream CA validates by looking for the upstream-derived TXT.

### The DNS-01 mismatch problem

1. Certbot (or other ACME client) computes TXT using its gateway account key
2. Certbot publishes that TXT to DNS
3. Gateway forwards the order to the upstream CA using the gateway's upstream account key
4. Upstream CA expects the upstream-derived TXT value
5. Mismatch → validation fails with "Correct value not found" even though a TXT record exists

This failure occurs even when DNS propagation is successful, because the TXT value is wrong from the CA's perspective.

### Why clients cannot solve this themselves

- Clients do not have access to the gateway's upstream account private key
- They have no way to compute the upstream-derived TXT value
- The gateway must compute it and ensure it's published to DNS

## Decision

The gateway manages DNS-01 TXT publication for orders routed to upstream CAs via operator-provided hook scripts.

**Hook interface:**

- **Deploy phase** (called before upstream challenge): Hook receives `CERTBOT_DOMAIN`, `CERTBOT_VALIDATION` (the upstream-derived TXT value), and publishes a TXT record to `_acme-challenge.<domain>`.
- **Cleanup phase** (called after validation): Hook removes the TXT record.

**Hook execution:**

- Per-upstream configuration: `upstreams.<id>.dns_hook.{deploy_script, cleanup_script}`
- Scripts run as the gateway process user, in the gateway's working directory
- Standard environment: `CERTBOT_DOMAIN`, `CERTBOT_VALIDATION`, `CERTBOT_TOKEN`
- Alternative environment: `ACME_GATEWAY_*` prefixes for compatibility
- Both TXT records coexist in DNS (client-derived and upstream-derived)

**For clients with no DNS-01 support:**

Clients that don't perform their own DNS-01 publishing (or that delegate it to the gateway) will rely entirely on the hook for TXT publication. The hook must succeed for validation to proceed.

## Rationale

- **Necessary for RFC 8555 compliance** under account-bound routing. Without hooks, dns-01 cannot succeed against strict upstreams.
- **Operator control** over DNS infrastructure. The operator chooses how to publish TXT records (API calls, CLI tools, database updates, etc.).
- **Non-invasive for clients.** Standard ACME clients require no modification; they publish their own version (which is harmless but ignored by the CA).
- **Minimal gateway complexity.** Hook execution is straightforward shell script invocation; all DNS-specific logic lives in operator-provided scripts.
- **Testing-friendly.** Example hooks for BIND (nsupdate), Route53, Cloudflare, Excedo simplify operator onboarding.

## Alternatives considered

| Alternative | Reason not chosen |
|---|---|
| Gateway computes and publishes directly (embedded DNS API support) | Violates principle of separation of concerns; every DNS provider would need a plugin |
| Extend ACME protocol to return upstream-derived TXT to client | Non-standard; requires all clients to be modified and aware of the proxy |
| Skip account-bound routing; use shared upstream account for all clients | Reintroduces original problem: account-context mismatch from ADR 0004 |
| Require all clients to call separate DNS provisioning API | Adds client-side complexity; defeats the purpose of a transparent ACME gateway |

## Consequences

- **Operational requirement** — operators must configure DNS hooks for any upstream using dns-01
- **Example scripts** reduce onboarding burden for common DNS providers (BIND, Route53, Cloudflare, Excedo, etc.)
- **Deploy failures propagate** — if a hook fails during the deploy phase, the entire order fails; ops must debug DNS access/permissions
- **Cleanup failures are soft** — treated as non-fatal (already validated), but leave dangling DNS records (consider monitoring)
- **DNS propagation overhead** — additional 1-2 seconds per order for hook execution + DNS propagation
- **Two TXT records in DNS during validation** — both client-derived and upstream-derived values coexist; this is safe and expected

## Follow-up

- Monitor hook execution times and failure rates in production
- Consider adding structured logging for hook invocations (start, end, exit code, output)
- Evaluate whether per-challenge hook parallelization would improve performance for high-volume orders
- Consider a "dry-run" mode for operators to test hooks before production rollout
