# DNS Hook Commands for E2E Tests

Use compiled binaries from [danieldonoghue/acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks). This keeps dns-01 hooks consistent with containerized runtime behavior.

## Build hook binaries

```bash
git clone https://github.com/danieldonoghue/acme-gateway-hooks.git
cd acme-gateway-hooks
make build-local
export ACME_HOOKS_BIN_DIR="$PWD/dist/bin-local"
```

## E2E dns01 (local Pebble + BIND)

Use `make test-e2e-dns01` with `ACME_HOOKS_BIN_DIR`:

```bash
cd /path/to/acme-gateway
make test-e2e-dns01 ACME_HOOKS_BIN_DIR="$ACME_HOOKS_BIN_DIR"
```

## E2E staging (choose provider explicitly)

Set common staging vars first:

```bash
cd /path/to/acme-gateway
export ACME_E2E_DOMAIN=staging.example.com
export ACME_E2E_EMAIL=ops@example.com
```

Option A: BIND / RFC2136

```bash
export ACME_E2E_DNS_PRESENT_CMD="BIND_DNS_SERVER=ns1.example.net:53 BIND_DNS_ZONE=example.com $ACME_HOOKS_BIN_DIR/bind-dns-deploy"
export ACME_E2E_DNS_CLEANUP_CMD="BIND_DNS_SERVER=ns1.example.net:53 BIND_DNS_ZONE=example.com $ACME_HOOKS_BIN_DIR/bind-dns-cleanup"
make test-e2e-staging
```

## Legacy shell templates (optional)

This directory still contains shell templates:
- `dns_present.sh`
- `dns_cleanup.sh`

You can still use them if needed:

```bash
cp dns_present.sh your_dns_present.sh
cp dns_cleanup.sh your_dns_cleanup.sh
$EDITOR your_dns_present.sh your_dns_cleanup.sh

export ACME_E2E_DNS_PRESENT_CMD='sh test/e2e/examples/your_dns_present.sh'
export ACME_E2E_DNS_CLEANUP_CMD='sh test/e2e/examples/your_dns_cleanup.sh'
```
