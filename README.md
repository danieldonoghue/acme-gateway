# acme-gateway

An ACMEv2 (RFC 8555) gateway that presents a standard ACME server to any ACME client and, based on configurable routing rules, re-originates requests to one of several upstream certificate authorities.

## RFC 8555 Compliance

acme-gateway implements the core ACME issuance flow with RFC 8555 compliance for supported operations. Key conformance points include:
- Challenge responses include both `rel="index"` and `rel="up"` Link headers (RFC 8555 §7.1, §7.5.1)
- All ACME resources are properly linked to their parent resources via Link headers
- Full support for identifier validation challenges (http-01, dns-01)
- Account key binding and anti-replay protection via nonce and JWS

**Note**: The gateway does not implement all RFC 8555 endpoints. See [BACKLOG.md](BACKLOG.md) for a list of unsupported operations (account deactivation, key rollover, etc.).

The gateway is tested against Pebble (IETF ACME test suite) to ensure compatibility with standard ACME clients like certbot.

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

## DNS Hooks

DNS hooks are operator-provided executables used for dns-01 TXT publication.

Scope limitation (intentional): for each configured upstream, acme-gateway executes exactly one dns hook implementation (one deploy script and one cleanup script). The gateway does not auto-detect authoritative DNS service from SOA/NS data and does not perform per-domain provider selection internally.

If an upstream must support domains hosted across multiple DNS providers, that provider-routing logic must be implemented externally by the configured hook command itself.

Preferred implementation: use the standalone hooks repository at [danieldonoghue/acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks). It provides compiled hook binaries designed for containerized deployments where shell interpreters are often unavailable.

- Configure `upstreams.<name>.dns_hook` for client orders routed to dns-01 upstreams.
- Configure `bootstrap.dns_hook` only when `bootstrap.enabled: true`.
- Hook commands receive `CERTBOT_DOMAIN`, `CERTBOT_VALIDATION`, and `CERTBOT_TOKEN` (plus `ACME_GATEWAY_*` aliases).

Why this exists: with account-bound upstream routing, upstream CAs validate TXT values derived from the gateway's upstream account key, not the client's key. The gateway must publish the upstream-derived TXT value.

Details:
- Architecture and decision rationale: [docs/decisions/0005-gateway-managed-dns01-hooks.md](docs/decisions/0005-gateway-managed-dns01-hooks.md)
- Product limitation decision: [docs/decisions/0006-single-dns-provider-per-upstream.md](docs/decisions/0006-single-dns-provider-per-upstream.md)
- Preferred compiled hooks: [danieldonoghue/acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks)
- Legacy shell templates: [packaging/hooks.d/examples](packaging/hooks.d/examples)
- E2E hook command guide: [test/e2e/examples/README.md](test/e2e/examples/README.md)

## Configuration

See [config.yaml.example](config.yaml.example) for the full annotated configuration.

### Key concepts
**Upstream profile mapping** — Per routing rule:
- Omit `upstream_profile` → strip (send no profile field upstream, CA uses its default)
- `upstream_profile: "name"` → always send this name upstream (override)
- `upstream_profile: "$passthrough"` → forward the inbound profile verbatim

**Upstream account routing for new orders** — New orders are bound to a dedicated upstream account per gateway ACME account (`upstream_id + account_id`) so challenge/account context stays consistent for strict `dns-01` validation. This avoids account-context mismatches when proxying to Let's Encrypt. See docs/decisions/0004-upstream-account-bound-routing-for-dns01.md.

**Multiple accounts per upstream (`account_count`)** — `account_count` remains as a compatibility mechanism for legacy slot-routed orders (`upstream_slot >= 0`) and fallback paths. For current account-bound order creation, the gateway resolves upstream account by gateway account identity instead of round-robin slot selection.

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

Set `server.tls: false` to disable TLS termination at the gateway entirely. The gateway listens on plain HTTP and expects a Kubernetes Ingress controller, cloud load balancer, or service mesh to terminate HTTPS externally. `base_url` must still begin with `https://` — ACME clients connect via HTTPS through the external terminator and that URL is signed into JWS requests. `bootstrap` must also be disabled in this mode.

### DNS hook commands

Bootstrap uses the same dns-01 hook mechanism documented in [DNS Hooks](README.md#dns-hooks). Configure `bootstrap.dns_hook` when `bootstrap.enabled: true`.

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

### Kubernetes

Two deployment methods are provided under [`deploy/`](deploy/README.md):

| Method | Best for |
|--------|----------|
| **Helm** (`deploy/helm/acme-gateway/`) | Getting started quickly; `values.yaml` drives the full config |
| **Kustomize** (`deploy/kustomize/`) | Platform teams managing plain YAML in source control |

Both handle the key Kubernetes concerns automatically: `strategy: Recreate` (SQLite is single-writer), non-privileged container port `8443` with the Service mapping `443 → 8443`, non-root security context with read-only root filesystem, and a PVC for the SQLite state database.

Kustomize overlays provided:

| Overlay | TLS mode | Use when |
|---------|----------|---------|
| `overlays/production` | Gateway-terminated (existing Secret) | Bare-metal / cloud LB with your own cert |
| `overlays/staging` | Gateway-terminated (existing Secret) | Non-production mirror of the above |
| `overlays/external-tls` | External termination (`server.tls: false`) | Ingress controller or cloud LB handles TLS |

**Helm quick start:**
```bash
helm install acme-gateway ./deploy/helm/acme-gateway \
  --namespace acme-gateway --create-namespace \
  --set config.server.baseURL=https://acme-gateway.example.com \
  --set config.upstreams.letsencrypt.contactEmail=ops@example.com \
  --set tls.existingSecret=acme-gateway-tls   # or tls.certManager.enabled=true
```

**Kustomize quick start:**
```bash
# Edit deploy/kustomize/overlays/production/config.yaml, then supply tls.crt + tls.key
kubectl apply -k deploy/kustomize/overlays/production
```

See [deploy/README.md](deploy/README.md) for full documentation including TLS certificate options (cert-manager, existing Secret, or bootstrap dns-01).

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

Before tagging, bump the image version in the three deployment manifests. The
release workflow validates these match the tag and will fail loudly if they are
stale.

| File | Field |
|---|---|
| `deploy/helm/acme-gateway/Chart.yaml` | `appVersion` |
| `deploy/kustomize/overlays/production/kustomization.yaml` | `images[0].newTag` |
| `deploy/kustomize/overlays/staging/kustomization.yaml` | `images[0].newTag` |

```bash
VERSION=v1.2.3   # the version you're about to release

perl -i -pe "s/^appVersion:.*/appVersion: \"${VERSION}\"/" deploy/helm/acme-gateway/Chart.yaml
perl -i -pe "s/newTag:.*/newTag: ${VERSION}/"  deploy/kustomize/overlays/production/kustomization.yaml
perl -i -pe "s/newTag:.*/newTag: ${VERSION}/"  deploy/kustomize/overlays/staging/kustomization.yaml

git add deploy/helm/acme-gateway/Chart.yaml \
        deploy/kustomize/overlays/production/kustomization.yaml \
        deploy/kustomize/overlays/staging/kustomization.yaml
git commit -m "chore(release): bump deployment manifests to ${VERSION}"
git push
```

Then run the full test suite and tag:

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
| `acme-gateway_vX.Y.Z_linux_amd64.tar.gz` | Binary + systemd unit + config example + legacy shell DNS hook examples |
| `acme-gateway_vX.Y.Z_linux_arm64.tar.gz` | Same for arm64 |
| `acme-gateway_X.Y.Z_debian12_amd64.deb` | Debian 12 package |
| `acme-gateway_X.Y.Z_debian12_arm64.deb` | Debian 12 arm64 package |
| `acme-gateway_X.Y.Z_debian13_amd64.deb` | Debian 13 package |
| `acme-gateway_X.Y.Z_debian13_arm64.deb` | Debian 13 arm64 package |
| `checksums.txt` | SHA-256 checksums for all artifacts |

Tarballs place legacy shell hook examples under `hooks.d/examples/`; Debian packages install them under `/etc/acme-gateway/hooks.d/examples/`.

For production/container deployments, prefer compiled binaries from [danieldonoghue/acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks).

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
make test-e2e-dns01     # Pebble dns-01 with real DNS validation via local BIND
make test-e2e-staging   # staging Let's Encrypt E2E (dns-01 via hooks)
make lint               # golangci-lint
make security           # govulncheck + gosec
```

### Local DNS-01 E2E setup (TestPebbleDNS01)

`make test-e2e-dns01` runs `TestPebbleDNS01` against Pebble with **real dns-01 validation** using a local BIND DNS server.

Prerequisites:
- Docker with `docker-compose` v2
- Built hook binaries from [danieldonoghue/acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks)

Build once:

```bash
cd ../acme-gateway-hooks
make build-local
cd ../acme-gateway
export ACME_HOOKS_BIN_DIR="$(cd ../acme-gateway-hooks && pwd)/dist/bin-local"
```

Run:
```bash
make test-e2e-dns01 ACME_HOOKS_BIN_DIR="$ACME_HOOKS_BIN_DIR"
```

This requires:
- `ACME_HOOKS_BIN_DIR/bind-dns-deploy`
- `ACME_HOOKS_BIN_DIR/bind-dns-cleanup`
- `BIND_DNS_SERVER=127.0.0.1:1053`
- `BIND_DNS_ZONE=pebble-test.local`

You can tune DNS behavior via `BIND_E2E_DNS_SERVER` and `BIND_E2E_DNS_ZONE`.

This test:
- Spins up BIND in a container (serves `pebble-test.local` zone)
- Creates an order for `test.pebble-test.local`
- Uses dns-01 challenge with `bind-dns-deploy`/`bind-dns-cleanup` to dynamically manage TXT records
- Forces Pebble to query BIND for validation (real DNS lookup, not fake)
- Validates end-to-end flow: account → order → challenge → DNS validation → cert

**Benefits over staging:**
- ✅ Fast (~10-20s vs 5-10 min)
- ✅ No internet required
- ✅ No LE infrastructure issues
- ✅ Repeatable, deterministic
- ✅ Great for CI/CD

See [test/e2e/bind/README.md](test/e2e/bind/README.md) for details and troubleshooting.

### Staging E2E setup

`make test-e2e-staging` runs `TestStagingLE` against real Let's Encrypt staging and requires dns-01 automation.

Required environment variables:

- `ACME_E2E_DOMAIN` — domain to issue (for example `staging.example.com`)
- `ACME_E2E_EMAIL` — ACME account contact email
- `ACME_E2E_DNS_PRESENT_CMD` — hook command that creates TXT for `_acme-challenge.<domain>`

Optional environment variables:

- `ACME_E2E_DNS_CLEANUP_CMD` — hook command to remove TXT after validation
- `ACME_E2E_DNS_TIMEOUT_SECONDS` — propagation timeout (default `300`)
- `ACME_E2E_DNS_POLL_SECONDS` — DNS poll interval (default `5`)
- `ACME_E2E_ORDER_TIMEOUT_SECONDS` — order readiness timeout (default `600`)
- `ACME_E2E_FINALIZE_TIMEOUT_SECONDS` — finalize-to-valid timeout (default `600`)

Hook command contract:

- Command runs via `sh -c` (for example a direct binary path or a shell wrapper).
- Positional args: `$1=<fqdn>`, `$2=<txt_value>`.
- Env vars include `ACME_E2E_PHASE`, `ACME_E2E_FQDN`, `ACME_E2E_DNS_VALUE`, `ACME_E2E_TOKEN`, `ACME_E2E_KEY_AUTHORIZATION`.

Example:

```bash
export ACME_E2E_DOMAIN=staging.example.com
export ACME_E2E_EMAIL=ops@example.com
export ACME_HOOKS_BIN_DIR='<absolute-path-to-acme-gateway-hooks>/dist/bin-local'

# BIND / RFC2136
export ACME_E2E_DNS_PRESENT_CMD="BIND_DNS_SERVER=ns1.example.net:53 BIND_DNS_ZONE=example.com $ACME_HOOKS_BIN_DIR/bind-dns-deploy"
export ACME_E2E_DNS_CLEANUP_CMD="BIND_DNS_SERVER=ns1.example.net:53 BIND_DNS_ZONE=example.com $ACME_HOOKS_BIN_DIR/bind-dns-cleanup"

make test-e2e-staging
```

Build the binaries from [danieldonoghue/acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks) first (for example `make build-local` in that repo for local e2e execution). For legacy shell templates and provider snippets, see [test/e2e/examples/README.md](test/e2e/examples/README.md).

## References

- [RFC 8555 — Automatic Certificate Management Environment (ACME)](https://www.rfc-editor.org/rfc/rfc8555)
- [draft-ietf-acme-profiles — ACME Order Profiles](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/)
