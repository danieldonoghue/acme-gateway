#!/bin/bash
# Example DNS hook script for publishing dns-01 TXT records in production.
# This is a template; replace with your actual DNS provider integration.
#
# The gateway calls this script with the following environment variables:
#   CERTBOT_DOMAIN        - Domain being validated (e.g., example.com)
#   CERTBOT_VALIDATION    - TXT record value to publish
#   CERTBOT_TOKEN         - Challenge token
#   ACME_GATEWAY_DOMAIN   - Alternative domain variable
#   ACME_GATEWAY_FQDN     - Fully qualified domain name (e.g., _acme-challenge.example.com)
#   ACME_GATEWAY_DNS_VALUE - TXT record value (same as CERTBOT_VALIDATION)
#   ACME_GATEWAY_TOKEN    - Challenge token (same as CERTBOT_TOKEN)
#
# Use either CERTBOT_* or ACME_GATEWAY_* variables; they contain the same values.

set -e

# Read from gateway-provided environment variables
DOMAIN="${CERTBOT_DOMAIN:-${ACME_GATEWAY_DOMAIN}}"
FQDN="${ACME_GATEWAY_FQDN}"
TXT_VALUE="${CERTBOT_VALIDATION:-${ACME_GATEWAY_DNS_VALUE}}"

if [ -z "$DOMAIN" ] || [ -z "$TXT_VALUE" ]; then
    echo "Usage: Called by acme-gateway with CERTBOT_DOMAIN, CERTBOT_VALIDATION env vars" >&2
    exit 1
fi

echo "[present] Publishing TXT record for $FQDN = $TXT_VALUE" >&2

# TODO: Replace with your DNS provider API calls.
# Examples:
#   - AWS Route53: aws route53 change-resource-record-sets ...
#   - Cloudflare: curl -X POST https://api.cloudflare.com/client/v4/zones/.../dns_records ...
#   - BIND nsupdate: echo "update add $FQDN 60 TXT $TXT_VALUE" | nsupdate -k /etc/bind/keys/update.key
#   - Cloudflare: curl -X POST https://api.cloudflare.com/client/v4/zones/.../dns_records ...
#   - nsupdate: echo "update add $FQDN 60 TXT $TXT_VALUE" | nsupdate ...
#   - Local test server: curl http://localhost:8053/update?name=$FQDN&value=$TXT_VALUE

# For testing without a real DNS provider, you can stub this:
# echo "Mock: would publish $FQDN = $TXT_VALUE"

exit 0
