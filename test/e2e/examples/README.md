# DNS Hook Examples for E2E Staging Tests

This directory contains example DNS hook scripts for running `make test-e2e-staging`.

## Files

- **dns_present.sh** — Template for publishing dns-01 TXT records
- **dns_cleanup.sh** — Template for removing dns-01 TXT records (idempotent)

## Using these examples

1. Copy and customize for your DNS provider:

```bash
cp dns_present.sh your_dns_present.sh
cp dns_cleanup.sh your_dns_cleanup.sh
$EDITOR your_dns_present.sh your_dns_cleanup.sh
```

2. Set environment variables and run the test:

```bash
export ACME_E2E_DOMAIN=staging.example.com
export ACME_E2E_EMAIL=ops@example.com
export ACME_E2E_DNS_PRESENT_CMD='bash test/e2e/examples/your_dns_present.sh'
export ACME_E2E_DNS_CLEANUP_CMD='bash test/e2e/examples/your_dns_cleanup.sh'
make test-e2e-staging
```

## DNS provider integrations

The hook scripts receive environment variables and must perform DNS updates. Common approaches:

### AWS Route53

```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456 \
  --change-batch file:///dev/stdin <<EOF
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$ACME_E2E_FQDN",
        "Type": "TXT",
        "TTL": 60,
        "ResourceRecords": [{"Value": "\"$ACME_E2E_DNS_VALUE\""}]
      }
    }
  ]
}
EOF
```

### Cloudflare

```bash
curl -X POST https://api.cloudflare.com/client/v4/zones/<zone_id>/dns_records \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"type\":\"TXT\",\"name\":\"$ACME_E2E_FQDN\",\"content\":\"$ACME_E2E_DNS_VALUE\"}"
```

### nsupdate (BIND)

```bash
echo "server <dns_server>"
echo "update add $ACME_E2E_FQDN 60 TXT $ACME_E2E_DNS_VALUE"
echo "send"
} | nsupdate -k /etc/bind/keys/update.key
```

### Local test DNS server

For local testing, run a simple test DNS server (e.g., [dnsmock](https://github.com/aio-libs/dnsmock)) and update it:

```bash
curl -X POST http://localhost:8053/update \
  -d "name=$ACME_E2E_FQDN&value=$ACME_E2E_DNS_VALUE"
```
