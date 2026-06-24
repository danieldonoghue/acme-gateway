# BIND DNS Server for ACME dns-01 Testing

This directory contains configuration for BIND (DNS server) used to support `TestPebbleDNS01`, which exercises the gateway's dns-01 challenge handling with **real DNS validation** (not Pebble's fake validator).

## Setup

### Prerequisites
- Docker with `docker-compose` v2
- Built binaries from [acme-gateway-hooks](https://github.com/danieldonoghue/acme-gateway-hooks)

### How It Works

1. **BIND Zone**: `pebble-test.local` zone is served by BIND in a container
2. **Dynamic Updates**: DNS hook binaries (`bind-dns-deploy`, `bind-dns-cleanup`) perform RFC2136 updates against BIND
3. **Pebble Validation**: When `PEBBLE_VA_ALWAYS_VALID=0`, Pebble queries BIND (via container DNS settings) to validate dns-01 challenges
4. **Gateway**: Routes challenge requests to Pebble, which validates against BIND

### Running the Test

```bash
# 1. Build hook binaries in acme-gateway-hooks (once)
# 2. Point ACME_HOOKS_BIN_DIR at the directory containing bind-dns-deploy and bind-dns-cleanup
export ACME_HOOKS_BIN_DIR="<absolute-path-to-acme-gateway-hooks>/dist/bin-local"

# 3. Run dns-01 e2e from this repo
make test-e2e-dns01 ACME_HOOKS_BIN_DIR="$ACME_HOOKS_BIN_DIR"
```

The test will:
1. Create an ACME account with the gateway
2. Create an order for `test.pebble-test.local`
3. Request a dns-01 challenge
4. Use `bind-dns-deploy` to add a TXT record to BIND
5. Trigger challenge validation (Pebble queries BIND)
6. Poll until challenge is valid
7. Finalize and retrieve certificate

## Configuration Files

- **`named.conf`**: BIND configuration
  - Authoritative for `pebble-test.local`
  - Allows dynamic updates via `nsupdate`
  - Binds to port 53/UDP and 53/TCP

- **`zones/pebble-test.local.zone`**: Zone file for test domain
  - SOA and NS records
  - Wildcard A record pointing to 127.0.0.1 (test harness)

## DNS Hook Commands

`make test-e2e-dns01` requires `ACME_HOOKS_BIN_DIR` to be set explicitly, and expects:
- `ACME_HOOKS_BIN_DIR/bind-dns-deploy`
- `ACME_HOOKS_BIN_DIR/bind-dns-cleanup`

It sets:
- `BIND_DNS_SERVER=127.0.0.1:1053`
- `BIND_DNS_ZONE=pebble-test.local`

You can override these in the make invocation:

```bash
make test-e2e-dns01 \
  ACME_HOOKS_BIN_DIR=/path/to/acme-gateway-hooks/dist/bin-local \
  BIND_E2E_DNS_SERVER=127.0.0.1:1053 \
  BIND_E2E_DNS_ZONE=pebble-test.local
```

Both target BIND at `127.0.0.1:1053` (host-mapped to the BIND container).

## Customizing

### Change Test Domain
Update `zones/pebble-test.local.zone` and modify `TestPebbleDNS01` to use the new domain.

### Use External DNS Server
Modify `docker-compose.yml` to point Pebble to a different nameserver:
```yaml
dns:
  - your-dns-server-ip:53
```

### Debug BIND
```bash
# View BIND logs
docker logs acme-gateway-bind-1

# Query BIND directly
dig @127.0.0.1 -p 53 test.pebble-test.local A
dig @127.0.0.1 -p 53 _acme-challenge.test.pebble-test.local TXT

# Test nsupdate
nsupdate <<EOF
server localhost 53
zone pebble-test.local
update add _acme-challenge.test.pebble-test.local 60 TXT "test-value"
send
EOF
```

## Comparison: TestPebbleDNS01 vs TestStagingLE

| Aspect | TestPebbleDNS01 | TestStagingLE |
|--------|----------------|---------------|
| **Upstream CA** | Pebble (local) | LE Staging (public) |
| **DNS Validation** | BIND (local) | LE's validators |
| **Speed** | ~10-20s | 5-10 minutes |
| **DNS Propagation** | Instant (localhost) | Internet latency + LE sync |
| **Reliability** | High (local, reproducible) | Depends on LE infrastructure |
| **Use Case** | CI/CD, rapid iteration | Final integration check |

## Troubleshooting

### Hook binary cannot reach BIND
- BIND container may not be ready
- Check `docker ps` to confirm `e2e-bind-1` container is running
- Confirm host mapping exists: `docker compose -f test/e2e/docker-compose.yml ps`
- Confirm `BIND_DNS_SERVER` is reachable (default `127.0.0.1:1053`)

### Pebble validation fails: "dns-01 query failed"
- Verify BIND zone file is correct
- Check TXT record was added: `docker compose -f test/e2e/docker-compose.yml exec bind dig _acme-challenge.test.pebble-test.local TXT`
- Ensure `PEBBLE_VA_ALWAYS_VALID=0` in environment (not 1)

### Container DNS resolution issues
- Restart containers: `docker compose -f test/e2e/docker-compose.yml down && docker compose -f test/e2e/docker-compose.yml up -d`
- Verify Pebble can reach BIND: `docker compose -f test/e2e/docker-compose.yml exec pebble nslookup pebble-test.local bind`

## Future Enhancements

- [ ] Support multiple test domains
- [ ] Add TLSA/SSHFP record support for other test scenarios
- [ ] Integrate DNSSEC validation testing
- [ ] Add metrics/monitoring to BIND container
