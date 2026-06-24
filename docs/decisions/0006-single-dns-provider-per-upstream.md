# ADR 0006: Single DNS provider implementation per upstream in acme-gateway

Status: Accepted
Date: 2026-06-24

## Context

acme-gateway supports gateway-managed dns-01 hooks as described in ADR 0005.
For each upstream, operators configure one deploy script and one cleanup script.

A recurring request is to have the gateway infer which authoritative DNS service
should be used for a given domain (for example by inspecting SOA/NS data) and
then select provider-specific behavior automatically.

In practice this is unreliable and expands scope beyond the gateway's core role:

- SOA/NS-based detection can identify delegation targets, but not always the
  correct provider account/tenant to use for API writes.
- NS naming patterns are not a stable provider identity contract.
- Delegations and CNAME-based challenge indirection can change provider context.
- Split-horizon and private DNS can make inference ambiguous or wrong.

## Decision

acme-gateway intentionally remains limited to one DNS hook implementation per
upstream configuration.

Specifically:

- The gateway executes the configured upstream deploy/cleanup hook paths.
- The gateway does not infer authoritative DNS provider from SOA/NS metadata.
- The gateway does not implement internal per-domain provider selection logic.

When an upstream must support domains spread across multiple DNS providers,
provider selection and dispatch are outside this repository's scope and must be
handled externally by the configured hook implementation.

## Rationale

- Keeps acme-gateway focused on ACME protocol translation, account binding, and
  upstream routing.
- Avoids nondeterministic provider inference failures in production.
- Preserves a clear and testable operator contract: one upstream, one hook
  implementation.
- Minimizes security and credential management complexity inside the gateway.
- Avoids concentrating large multi-provider credential sets inside a generic
  gateway process.

## Consequences

- Multi-provider DNS automation is not a first-class capability in this repo.
- Operators needing multi-provider support must provide external hook logic that
  implements domain-to-provider routing.
- Documentation must clearly state this limit to prevent incorrect assumptions.
- In certbot-oriented deployments, use scoped credential propagation where
  possible so hook executions receive only the provider credentials they need.

## Non-goals

- Building authoritative-provider autodiscovery from SOA/NS records.
- Adding internal provider plugin orchestration logic to acme-gateway.
- Changing the ACME client contract; clients remain gateway-transparent.
