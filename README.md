# acme-gateway

An ACMEv2 (RFC 8555) gateway that presents a standard ACME server to any ACME client and, based on configurable routing rules, re-originates requests to one of several upstream certificate authorities.

## Overview

`acme-gateway` solves the problem of routing certificate requests from a single ACME client configuration to different CAs:

| Client request | Routed to |
|---|---|
| `--preferred-profile tlsserver` | Let's Encrypt |
| `--preferred-profile shortlived` | Let's Encrypt (short-lived profile) |
| `--preferred-profile tlsclient --key-type rsa` | DigiCert (EAB set A) |
| `--preferred-profile tlsclient --key-type ecdsa` | DigiCert (EAB set B) |
| Domain ends in `.internal` | DigiCert (fallback) |

Certbot is pointed at `--server https://acme-gateway.internal/directory` and needs zero other changes.

## Architecture

```
Certbot ──ACMEv2──▶ acme-gateway ──ACMEv2──▶ Let's Encrypt
                         │         ──ACMEv2──▶ DigiCert (RSA)
                         │         ──ACMEv2──▶ DigiCert (ECDSA)
                         │
                     SQLite state
```

The gateway **terminates and re-originates** every ACME request. It maintains its own keypairs and accounts on each upstream CA; it never forwards client JWS directly.

## Requirements

- Go 1.25+
- A publicly resolvable domain for the gateway itself (if `bootstrap.enabled: true`)
- DNS hook scripts for dns-01 challenge provisioning

## Quick Start

```bash
# 1. Copy and edit the example config
cp config.yaml.example config.yaml
$EDITOR config.yaml

# 2. Set EAB credentials as environment variables
export DIGICERT_RSA_EAB_KID=...
export DIGICERT_RSA_EAB_HMAC=...
export DIGICERT_ECDSA_EAB_KID=...
export DIGICERT_ECDSA_EAB_HMAC=...

# 3. Build and run
go build -o acme-gateway ./cmd/acme-gateway
./acme-gateway -config config.yaml
```

## Configuration

See [config.yaml.example](config.yaml.example) for a fully annotated configuration file.

### Key concepts

**Profile namespace** — Profile names (`tlsserver`, `tlsclient`, etc.) are defined entirely by the operator in the `profiles` block. They are advertised in the gateway's `/directory` and have no required relationship to any upstream CA's profile names.

**Upstream profile mapping** — Per routing rule:
- Omit `upstream_profile` → strip (send no profile field upstream, CA uses its default)
- `upstream_profile: "name"` → always send this name upstream (override)
- `upstream_profile: "$passthrough"` → forward the inbound profile verbatim

**Routing signals** — Evaluated in priority order within each rule (all conditions ANDed):
1. `profile` — from `--preferred-profile` / `--required-profile` in Certbot 4.0+
2. `key_type` — RSA or ECDSA, detected from the account's registered public key
3. `domain_suffix` — suffix match on any identifier in the order

### Environment variable interpolation

Any config value may reference environment variables using `${VAR}` syntax:

```yaml
eab:
  key_id:   "${DIGICERT_RSA_EAB_KID}"
  hmac_key: "${DIGICERT_RSA_EAB_HMAC}"
```

## Bootstrap (gateway TLS certificate)

When `bootstrap.enabled: true`, the gateway obtains its own TLS certificate on first start via dns-01 before opening the HTTPS listener. Set `bootstrap.enabled: false` to provide the certificate externally.

### DNS hook scripts

Hook scripts are called with the same environment variables as Certbot's manual DNS hooks:

| Variable | Description |
|---|---|
| `CERTBOT_DOMAIN` | Domain being validated |
| `CERTBOT_VALIDATION` | TXT record value to set |
| `CERTBOT_TOKEN` | Challenge token |

The deploy script must be idempotent. The cleanup script is called after the challenge completes (success or failure).

## Deployment

### systemd

```bash
# Install binary
install -m 755 acme-gateway /usr/local/bin/

# Create service user
useradd -r -s /sbin/nologin acme-gateway

# Create directories
install -d -o acme-gateway /etc/acme-gateway /var/lib/acme-gateway

# Copy config and service file
cp config.yaml /etc/acme-gateway/
cp acme-gateway.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now acme-gateway
```

### Docker

```bash
docker build -t acme-gateway .
docker run -d \
  -p 443:443 \
  -v /etc/acme-gateway:/etc/acme-gateway \
  -v /var/lib/acme-gateway:/var/lib/acme-gateway \
  -e DIGICERT_RSA_EAB_KID=... \
  -e DIGICERT_RSA_EAB_HMAC=... \
  acme-gateway
```

## Operational Notes

- **Back up the SQLite database.** It contains the gateway's upstream account keypairs. Loss requires re-registration with each upstream CA.
- **EAB credentials are write-once per upstream account.** Rotating EAB credentials requires deleting the `upstream_accounts` row for that upstream and restarting.
- **Profile names are operator-defined.** Document your gateway's profile vocabulary in internal runbooks.
- **Nonces** expire after 10 minutes and are pruned on startup and every 15 minutes.
- **Structured JSON logging.** Every order logs: `account_id`, `upstream_id`, `routing_signal`, `profile`, `upstream_profile`, `order_id`, `identifiers`, `status`, `duration_ms`.

## Test Cases

See section 13 of the build specification for end-to-end test cases. Always use LE **staging** and a DigiCert test environment — never test against production LE.

## References

- [RFC 8555 — Automatic Certificate Management Environment (ACME)](https://www.rfc-editor.org/rfc/rfc8555)
- [draft-ietf-acme-profiles — ACME Order Profiles](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/)
