#!/bin/bash
# DNS hook for BIND via docker exec
# Adds a TXT record for dns-01 validation
#
# Usage: dns_present_pebble.sh <fqdn> <dnsValue>
# Environment: ACME_E2E_PHASE, ACME_E2E_FQDN, ACME_E2E_DNS_VALUE

set -e

FQDN="${ACME_E2E_FQDN:-$1}"
DNS_VALUE="${ACME_E2E_DNS_VALUE:-$2}"

if [ -z "$FQDN" ] || [ -z "$DNS_VALUE" ]; then
  echo "Usage: dns_present.sh <fqdn> <dnsValue>" >&2
  exit 1
fi

# Use docker exec to run nsupdate inside the bind container
docker exec e2e-bind-1 nsupdate <<EOF
server localhost 53
zone pebble-test.local
update add $FQDN 60 IN TXT "$DNS_VALUE"
send
EOF

echo "Added TXT record: $FQDN -> $DNS_VALUE"
