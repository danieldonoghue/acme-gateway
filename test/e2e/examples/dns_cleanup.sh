#!/bin/bash
# Example DNS cleanup hook script for removing dns-01 TXT records.
# This is a template; replace with your actual DNS provider integration.
#
# Environment variables available:
#   ACME_E2E_PHASE               - "cleanup"
#   ACME_E2E_FQDN                - Full qualified domain name (e.g., _acme-challenge.example.com)
#   ACME_E2E_DNS_VALUE           - TXT record value that was set
#   ACME_E2E_TOKEN               - Challenge token
#   ACME_E2E_KEY_AUTHORIZATION   - Full key authorization
#
# Positional arguments:
#   $1 - FQDN
#   $2 - TXT value

set -e

FQDN="$1"
TXT_VALUE="$2"

if [ -z "$FQDN" ]; then
    echo "Usage: $0 <fqdn>" >&2
    exit 1
fi

echo "[cleanup] Removing TXT record for $FQDN" >&2

# TODO: Replace with your DNS provider API calls to delete the TXT record.
# Must be idempotent (safe to call even if record doesn't exist).

# For testing without a real DNS provider, you can stub this:
# echo "Mock: would remove TXT record for $FQDN"

exit 0
