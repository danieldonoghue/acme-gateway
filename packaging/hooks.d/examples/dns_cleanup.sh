#!/bin/bash
# Example DNS cleanup hook script for removing dns-01 TXT records in production.
# This is a template; replace with your actual DNS provider integration.
#
# The gateway calls this script with the following environment variables:
#   CERTBOT_DOMAIN        - Domain being validated (e.g., example.com)
#   CERTBOT_VALIDATION    - TXT record value that was published
#   CERTBOT_TOKEN         - Challenge token
#   ACME_GATEWAY_DOMAIN   - Alternative domain variable
#   ACME_GATEWAY_FQDN     - Fully qualified domain name (e.g., _acme-challenge.example.com)
#   ACME_GATEWAY_DNS_VALUE - TXT record value (same as CERTBOT_VALIDATION)
#   ACME_GATEWAY_TOKEN    - Challenge token (same as CERTBOT_TOKEN)
#
# Use either CERTBOT_* or ACME_GATEWAY_* variables; they contain the same values.
# This script must be idempotent: safe to call even if the record was already removed.

set -e

# Read from gateway-provided environment variables
DOMAIN="${CERTBOT_DOMAIN:-${ACME_GATEWAY_DOMAIN}}"
FQDN="${ACME_GATEWAY_FQDN}"
TXT_VALUE="${CERTBOT_VALIDATION:-${ACME_GATEWAY_DNS_VALUE}}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: Called by acme-gateway with CERTBOT_DOMAIN env var" >&2
    exit 1
fi

echo "[cleanup] Removing TXT record for $FQDN" >&2

# TODO: Replace with your DNS provider API calls to delete the TXT record.
# Must be idempotent (safe to call even if record doesn't exist).
# Examples:
#   - AWS Route53: aws route53 change-resource-record-sets ...
#   - Cloudflare: curl -X DELETE https://api.cloudflare.com/client/v4/zones/.../dns_records/<id>
#   - BIND nsupdate: echo "update delete $FQDN TXT $TXT_VALUE" | nsupdate -k /etc/bind/keys/update.key

# For testing without a real DNS provider, you can stub this:
# echo "Mock: would remove TXT record for $FQDN"

exit 0
