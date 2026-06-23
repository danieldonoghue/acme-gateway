#!/bin/bash
# Example DNS hook script for publishing dns-01 TXT records.
# This is a template; replace with your actual DNS provider integration.
#
# Environment variables available:
#   ACME_E2E_PHASE               - "present" or "cleanup"
#   ACME_E2E_FQDN                - Full qualified domain name (e.g., _acme-challenge.example.com)
#   ACME_E2E_DNS_VALUE           - TXT record value to set
#   ACME_E2E_TOKEN               - Challenge token
#   ACME_E2E_KEY_AUTHORIZATION   - Full key authorization
#
# Positional arguments:
#   $1 - FQDN
#   $2 - TXT value

set -e

FQDN="$1"
TXT_VALUE="$2"

if [ -z "$FQDN" ] || [ -z "$TXT_VALUE" ]; then
    echo "Usage: $0 <fqdn> <txt_value>" >&2
    exit 1
fi

echo "[$ACME_E2E_PHASE] Setting TXT record for $FQDN = $TXT_VALUE" >&2

# TODO: Replace with your DNS provider API calls.
# Examples:
#   - AWS Route53: aws route53 change-resource-record-sets ...
#   - Cloudflare: curl -X POST https://api.cloudflare.com/client/v4/zones/.../dns_records ...
#   - nsupdate: echo "update add $FQDN 60 TXT $TXT_VALUE" | nsupdate ...
#   - Local test server: curl http://localhost:8053/update?name=$FQDN&value=$TXT_VALUE

# For testing without a real DNS provider, you can stub this:
# echo "Mock: would publish $FQDN = $TXT_VALUE"

exit 0
