# acme-gateway

An ACMEv2 (RFC 8555) gateway that presents a standard ACME server to any ACME client and, based on configurable routing rules, re-originates requests to one of several upstream certificate authorities.

## Overview

`acme-gateway` solves the problem of routing certificate requests from a single ACME client configuration to different CAs:

| Client request | Routed to |
|---|---|
| `--preferred-profile tlsserver` | Let's Encrypt |
| `--preferred-profile shortlived` | Let's Encrypt (short-lived profile) |
| `--preferred-profile tlsclient --key-type rsa` | Private CA (EAB set A) |
| `--preferred-profile tlsclient --key-type ecdsa` | Private CA (EAB set B) |
| Domain ends in `.internal` | Private CA (fallback) |

Certbot is pointed at `--server https://acme-gateway.internal/directory` and needs zero other changes.

## Architecture

```
Certbot ──ACMEv2──▶ acme-gateway ──ACMEv2──▶ Let's Encrypt
                         │         ──ACMEv2──▶ Private CA (RSA)
                         │         ──ACMEv2──▶ Private CA (ECDSA)
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
export PRIVATE_CA_RSA_EAB_KID=...
export PRIVATE_CA_RSA_EAB_HMAC=...
export PRIVATE_CA_ECDSA_EAB_KID=...
export PRIVATE_CA_ECDSA_EAB_HMAC=...

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

**Multiple accounts per upstream (`account_count`)** — Let's Encrypt allows 50 new orders per account per 3-hour window. A fleet where every server renews at the start of the month might exhaust that quota quicky. `account_count: N` tells the gateway to maintain N independent ACME accounts at an upstream and distribute new orders across them round-robin. Each account's keypair and registration URL are persisted in the SQLite database; the account slot is stored with every order so that subsequent operations (authz, finalize, cert, revoke) always use the matching keypair.

```yaml
upstreams:
  letsencrypt:
    directory_url: "https://acme-v02.api.letsencrypt.org/directory"
    contact_email: "certadmin@example.com"
    account_count: 3   # spreads load across 3 accounts → 150 orders/3h headroom
```

`account_count` is only valid for upstreams without EAB (each ACME account requires its own unique EAB credential; for EAB upstreams configure separate upstream entries instead). Defaults to 1.

**Private CA TLS trust (`ca_cert_path`)** — By default, the gateway uses the system certificate pool when connecting to upstream ACME directories. If your upstream CA presents a TLS certificate signed by a private root (common for internal CAs and for Pebble in test environments), provide the CA certificate in PEM format:

```yaml
upstreams:
  private-ca:
    directory_url: "https://acme.your-private-ca.example/directory"
    contact_email: "certadmin@example.com"
    ca_cert_path: "/etc/acme-gateway/private-ca.pem"  # appended to system pool
    eab:
      key_id:   "${PRIVATE_CA_EAB_KID}"
      hmac_key: "${PRIVATE_CA_EAB_HMAC}"
```

The certificate at `ca_cert_path` is added **in addition to** the system pool, so standard public CAs still work. The file is read once at startup; restart the gateway if the CA certificate is rotated.

**Routing signals** — Evaluated in priority order within each rule (all conditions ANDed):
1. `profile` — from `--preferred-profile` / `--required-profile` in Certbot 4.0+
2. `key_type` — RSA or ECDSA, detected from the account's registered public key
3. `domain_suffix` — suffix match on any identifier in the order

### Environment variable interpolation

Any config value may reference environment variables using `${VAR}` syntax:

```yaml
eab:
  key_id:   "${PRIVATE_CA_RSA_EAB_KID}"
  hmac_key: "${PRIVATE_CA_RSA_EAB_HMAC}"
```

## Bootstrap (gateway TLS certificate)

When `bootstrap.enabled: true`, the gateway obtains its own TLS certificate on first start via dns-01 before opening the HTTPS listener and renews it automatically.

Set `bootstrap.enabled: false` to provide the certificate externally (cert-manager, Ansible, manual). The gateway loads `cert_path`/`key_path` once at startup. **There is no live reload for the external path** — if the files are rewritten by an external renewer, the gateway must be restarted to serve the new certificate. See docs/decisions/0003-no-live-reload-external-cert.md

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
  -e PRIVATE_CA_RSA_EAB_KID=... \
  -e PRIVATE_CA_RSA_EAB_HMAC=... \
  acme-gateway
```

## Operational Notes

- **Back up the SQLite database.** It contains the gateway's upstream account keypairs. Loss requires re-registration with each upstream CA.
- **EAB credentials are write-once per upstream account.** Rotating EAB credentials requires deleting the `upstream_accounts` row for that upstream (`DELETE FROM upstream_accounts WHERE upstream_id = 'name' AND slot = 0`) and restarting.
- **Profile names are operator-defined.** Document your gateway's profile vocabulary in internal runbooks.
- **Nonces** expire after 10 minutes and are pruned on startup and every 15 minutes.
- **Structured JSON logging.** Every order logs: `account_id`, `upstream_id`, `routing_signal`, `profile`, `upstream_profile`, `order_id`, `identifiers`, `status`, `duration_ms`.

## Test Cases

Always test against LE **staging** (`https://acme-staging-v02.api.letsencrypt.org/directory`) and a private CA test environment — never against production LE.

| # | Scenario | Routing signal | Expected upstream |
|---|---|---|---|
| TC-1 | `--preferred-profile tlsserver` | profile | Let's Encrypt, upstream profile `tlsserver` |
| TC-2 | `--preferred-profile shortlived` | profile | Let's Encrypt, upstream profile `shortlived` |
| TC-3 | `--required-profile tlsclient --key-type rsa` | profile + key type | Private CA (EAB set A, RSA) |
| TC-4 | `--required-profile tlsclient --key-type ecdsa` | profile + key type | Private CA (EAB set B, ECDSA) |
| TC-5 | No profile, domain ends in `.internal` | domain suffix | Private CA (RSA) |
| TC-6 | Verify `upstream_profile` strip / override / passthrough | — | Confirm via gateway logs or upstream request capture |
| TC-7 | `certbot renew` | — | Each cert renewed via same upstream as original issuance |
| TC-8 | First start with `bootstrap.enabled: true`, no cert on disk | — | Bootstrap dns-01 flow runs; HTTPS listener starts |
| TC-9 | Cert within renewal window | — | Background goroutine renews and reloads cert without restart |

## Release

Releases are produced automatically by the [release workflow](.github/workflows/release.yml) when a `v`-prefixed tag is pushed.

### Cutting a release

```bash
# Ensure master is clean and all tests pass.
git checkout master && git pull
make test
make test-e2e

# Tag using semantic versioning.
git tag v1.2.3
git push origin v1.2.3
```

The workflow will:
1. Run tests and `govulncheck` as a preflight gate
2. Cross-compile `linux/amd64` and `linux/arm64` binaries with version/commit/date embedded
3. Build four `.deb` packages — Debian 12 (bookworm) and 13 (trixie) × amd64 and arm64
4. Build and push a multi-arch distroless Docker image to GHCR
5. Create a GitHub release with all artifacts and auto-generated release notes

### Release artifacts

| Artifact | Description |
|---|---|
| `acme-gateway_vX.Y.Z_linux_amd64.tar.gz` | Binary + systemd unit + config example |
| `acme-gateway_vX.Y.Z_linux_arm64.tar.gz` | Same for arm64 |
| `acme-gateway_X.Y.Z_debian12_amd64.deb` | Debian 12 package |
| `acme-gateway_X.Y.Z_debian12_arm64.deb` | Debian 12 arm64 package |
| `acme-gateway_X.Y.Z_debian13_amd64.deb` | Debian 13 package |
| `acme-gateway_X.Y.Z_debian13_arm64.deb` | Debian 13 arm64 package |
| `checksums.txt` | SHA-256 checksums for all artifacts |

Docker images are pushed to `ghcr.io/danieldonoghue/acme-gateway` with tags `vX.Y.Z`, `X.Y`, and `X`.

### Pre-releases

Tags containing a hyphen (e.g. `v1.0.0-rc.1`) are marked as pre-releases on GitHub automatically.

### Local build

```bash
make build-linux    # cross-compile both arches to dist/
make deb            # build .deb packages via Docker (required on macOS)
make docker         # build + push multi-arch image (requires docker buildx)
make test               # run unit tests with race detector
make test-e2e           # end-to-end tests against Pebble (requires Docker)
make test-e2e-staging   # staging Let's Encrypt E2E (requires internet + DNS)
make lint               # golangci-lint
make security           # govulncheck + gosec
```

## References

- [RFC 8555 — Automatic Certificate Management Environment (ACME)](https://www.rfc-editor.org/rfc/rfc8555)
- [draft-ietf-acme-profiles — ACME Order Profiles](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/)
