# BIND DNS Server for ACME dns-01 Testing

This directory contains configuration for BIND (DNS server) used to support `TestPebbleDNS01`, which exercises the gateway's dns-01 challenge handling with **real DNS validation** (not Pebble's fake validator).

## Setup

### Prerequisites
- Docker with `docker-compose` v2
- `nsupdate` tool (usually pre-installed; if not: `brew install bind` on macOS or `apt-get install dnsutils` on Linux)

### How It Works

1. **BIND Zone**: `pebble-test.local` zone is served by BIND in a container
2. **Dynamic Updates**: DNS hooks use `nsupdate` to add/delete TXT records on the fly
3. **Pebble Validation**: When `PEBBLE_VA_ALWAYS_VALID=0`, Pebble queries BIND (via container DNS settings) to validate dns-01 challenges
4. **Gateway**: Routes challenge requests to Pebble, which validates against BIND

### Running the Test

```bash
# 1. Enable real DNS validation in Pebble (default is 1, which skips validation)
export PEBBLE_VA_ALWAYS_VALID=0

# 2. Enable the dns-01 test
export ACME_E2E_PEBBLE_DNS=1

# 3. Run e2e tests
make test-e2e
```

The test will:
1. Create an ACME account with the gateway
2. Create an order for `test.pebble-test.local`
3. Request a dns-01 challenge
4. Use `nsupdate` to add a TXT record to BIND
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

## DNS Hooks

Hooks are in `../examples/`:
- **`dns_present_pebble.sh`**: Adds TXT record via `nsupdate`
- **`dns_cleanup_pebble.sh`**: Removes TXT record via `nsupdate`

Both target BIND at `localhost:53` (from test host perspective, this is the BIND container).

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

### `nsupdate` fails: "connection refused"
- BIND container may not be ready
- Check `docker ps` to confirm `e2e-bind-1` container is running
- Wait a few seconds and retry
- List containers: `docker compose -f test/e2e/docker-compose.yml ps`

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
