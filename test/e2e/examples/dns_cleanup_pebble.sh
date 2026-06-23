#!/bin/bash
# DNS cleanup hook for BIND via docker exec
# Removes a TXT record after dns-01 validation
#
# Usage: dns_cleanup.sh <fqdn> <dnsValue>
# Environment: ACME_E2E_PHASE, ACME_E2E_FQDN, ACME_E2E_DNS_VALUE

set -e

FQDN="${ACME_E2E_FQDN:-$1}"
DNS_VALUE="${ACME_E2E_DNS_VALUE:-$2}"

if [ -z "$FQDN" ] || [ -z "$DNS_VALUE" ]; then
  echo "Usage: dns_cleanup.sh <fqdn> <dnsValue>" >&2
  exit 1
fi

# Use docker exec to run nsupdate inside the bind container
docker exec e2e-bind-1 nsupdate <<EOF
server localhost 53
zone pebble-test.local
update delete $FQDN TXT "$DNS_VALUE"
send
EOF

echo "Deleted TXT record: $FQDN"
