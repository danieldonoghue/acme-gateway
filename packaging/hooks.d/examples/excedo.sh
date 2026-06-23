#!/bin/bash
#
# Excedo DNS Hook - DNS01 Challenge Management via Excedo API
#
# This hook script manages DNS01 ACME challenges for domains hosted on Excedo
# DNS infrastructure using their REST API. It adds and removes TXT records
# required for certificate validation.
#
# ENVIRONMENT VARIABLES (from acme-gateway or certbot):
#   CERTBOT_DOMAIN        - The domain being validated (e.g., example.com)
#   CERTBOT_VALIDATION    - The validation string for the TXT record
#   ACME_GATEWAY_DOMAIN   - Alternative domain variable (acme-gateway format)
#   ACME_GATEWAY_TOKEN    - Alternative validation variable (acme-gateway format)
#   EXCEDO_API_TOKEN      - Excedo API authentication token (REQUIRED)
#   EXCEDO_API_URL        - Excedo API base URL (default: https://api.domainname.systems)
#
# USAGE:
#   # Deploy mode (add TXT record)
#   export EXCEDO_API_TOKEN="your-token-here"
#   export CERTBOT_DOMAIN="example.com"
#   export CERTBOT_VALIDATION="validation-string"
#   ./excedo.sh
#   # or explicitly:
#   ./excedo.sh deploy
#
#   # Cleanup mode (remove TXT record)
#   ./excedo.sh cleanup
#
# CONFIGURATION:
#   Required: Set EXCEDO_API_TOKEN as an environment variable or in config.yaml
#   Optional: Set EXCEDO_API_URL if using a non-standard Excedo API endpoint
#   (default is https://api.domainname.systems)
#
# SETUP:
#   1. Obtain an API token from your Excedo dashboard
#   2. Set EXCEDO_API_TOKEN in your acme-gateway config.yaml or environment
#   3. Ensure curl is installed and can reach the Excedo API endpoint
#
# ERROR HANDLING:
#   - Deploy: Exits with error (1) if TXT record cannot be added
#   - Cleanup: Idempotent — exits successfully even if record doesn't exist or cleanup fails
#

set -e

# ──────────────────────────────────────────────────────────────────────────────
# Environment variables
# ──────────────────────────────────────────────────────────────────────────────

FQDN="${CERTBOT_DOMAIN:-$ACME_GATEWAY_DOMAIN}"
VALIDATION="${CERTBOT_VALIDATION:-$ACME_GATEWAY_TOKEN}"
API_TOKEN="${EXCEDO_API_TOKEN}"
API_URL="${EXCEDO_API_URL:-https://api.domainname.systems}"
MODE="${1:-deploy}"

# ──────────────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────────────

if [ -z "$FQDN" ]; then
    echo "Error: CERTBOT_DOMAIN (or ACME_GATEWAY_DOMAIN) not set" >&2
    exit 1
fi

if [ -z "$VALIDATION" ]; then
    echo "Error: CERTBOT_VALIDATION (or ACME_GATEWAY_TOKEN) not set" >&2
    exit 1
fi

if [ -z "$API_TOKEN" ]; then
    echo "Error: EXCEDO_API_TOKEN not set" >&2
    exit 1
fi

# ──────────────────────────────────────────────────────────────────────────────
# Functions
# ──────────────────────────────────────────────────────────────────────────────

# Authenticate with Excedo API and return session token
authenticate() {
    local auth_response
    auth_response=$(curl -s -X GET "${API_URL}/authenticate/login/${API_TOKEN}")
    
    if ! echo "$auth_response" | grep -q '"code":1000'; then
        echo "Error: Excedo authentication failed" >&2
        echo "Response: $auth_response" >&2
        return 1
    fi
    
    local session_token
    session_token=$(echo "$auth_response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
    
    if [ -z "$session_token" ]; then
        echo "Error: Could not extract session token from Excedo response" >&2
        return 1
    fi
    
    echo "$session_token"
}

# Extract zone name and record name for this FQDN
parse_zone_and_record() {
    local fqdn="$1"
    
    # Remove leading _acme-challenge. prefix to get initial zone candidate
    local zone_name="${fqdn#_acme-challenge.}"
    
    # For subdomains, extract just the last two labels (domain.tld)
    if [[ "$zone_name" == *.* ]]; then
        local IFS='.'
        local -a parts=($zone_name)
        if [ "${#parts[@]}" -gt 2 ]; then
            zone_name="${parts[-2]}.${parts[-1]}"
        fi
    fi
    
    # Extract the record name (relative to zone)
    local record_name="${fqdn%.$zone_name}"
    if [ "$record_name" = "$fqdn" ]; then
        record_name="$fqdn"
    fi
    
    echo "$zone_name:$record_name"
}

# Deploy: add TXT record
deploy_record() {
    local fqdn="$1"
    local validation="$2"
    local session_token="$3"
    
    local zone_info
    zone_info=$(parse_zone_and_record "$fqdn")
    local zone_name="${zone_info%:*}"
    local record_name="${zone_info#*:}"
    
    echo "[deploy] Publishing TXT record: $fqdn = $validation" >&2
    
    # Verify zone exists by fetching records
    local zone_response
    zone_response=$(curl -s -X GET "${API_URL}/dns/getrecords/${session_token}?domainname=${zone_name}")
    
    if ! echo "$zone_response" | grep -q '"code":1000'; then
        echo "Error: Could not fetch zone records for $zone_name from Excedo" >&2
        echo "Response: $zone_response" >&2
        return 1
    fi
    
    # Add the TXT record
    local add_response
    add_response=$(curl -s -X POST "${API_URL}/dns/addrecord/${session_token}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "type=TXT" \
        --data-urlencode "name=${record_name}" \
        --data-urlencode "content=${validation}" \
        --data-urlencode "ttl=120" \
        --data-urlencode "domainname=${zone_name}")
    
    if echo "$add_response" | grep -q '"code":1000'; then
        echo "[deploy] Successfully added TXT record for $fqdn" >&2
        return 0
    else
        echo "Error: Failed to add TXT record via Excedo API" >&2
        echo "Response: $add_response" >&2
        return 1
    fi
}

# Cleanup: remove TXT record (idempotent)
cleanup_record() {
    local fqdn="$1"
    local session_token="$2"
    local validation="$3"
    
    local zone_info
    zone_info=$(parse_zone_and_record "$fqdn")
    local zone_name="${zone_info%:*}"
    local record_name="${zone_info#*:}"
    
    echo "[cleanup] Removing TXT record for $fqdn" >&2

    if [ -z "$validation" ]; then
        echo "[cleanup] Warning: validation TXT value not provided; skipping to avoid deleting unrelated challenge records" >&2
        return 0
    fi
    
    # Authenticate (in case session expired)
    local auth_response
    auth_response=$(curl -s -X GET "${API_URL}/authenticate/login/${API_TOKEN}")
    
    if ! echo "$auth_response" | grep -q '"code":1000'; then
        echo "[cleanup] Warning: Excedo authentication failed, skipping cleanup" >&2
        return 0
    fi
    
    session_token=$(echo "$auth_response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
    if [ -z "$session_token" ]; then
        echo "[cleanup] Warning: Could not extract session token, skipping cleanup" >&2
        return 0
    fi
    
    # Get zone records
    local zone_response
    zone_response=$(curl -s -X GET "${API_URL}/dns/getrecords/${session_token}?domainname=${zone_name}")
    
    if ! echo "$zone_response" | grep -q '"code":1000'; then
        echo "[cleanup] Warning: Could not fetch zone records for $zone_name, skipping cleanup" >&2
        return 0
    fi
    
    # Find record IDs for this exact TXT value and challenge name.
    local record_ids
    record_ids=$(echo "$zone_response" | python3 - "$fqdn" "$record_name" "$validation" <<'PYTHON'
import json
import sys

try:
    data = json.loads(sys.stdin.read())
except Exception:
    sys.exit(0)

fqdn = sys.argv[1]
record_name = sys.argv[2]
validation = sys.argv[3]
zone_data = data.get("dns", {})
ids = []
seen = set()

def add_id(rec):
    rid = rec.get("recordid")
    if rid is None:
        return
    rid = str(rid)
    if rid in seen:
        return
    seen.add(rid)
    ids.append(rid)

# Find records matching the FQDN
for zone, records_list in zone_data.items():
    records = records_list.get("records", [])
    for rec in records:
        if str(rec.get("type", "")).upper() == "TXT":
            if str(rec.get("name", "")) in {fqdn, record_name} and str(rec.get("content", "")) == validation:
                add_id(rec)

print("\n".join(ids))
PYTHON
    )
    
    if [ -z "$record_ids" ]; then
        echo "[cleanup] Record $fqdn not found (already removed)" >&2
        return 0
    fi
    
    # Delete all matched TXT records.
    while IFS= read -r record_id; do
        [ -z "$record_id" ] && continue

        local delete_response
        delete_response=$(curl -s -X POST "${API_URL}/dns/deleterecord/${session_token}" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            --data-urlencode "recordid=${record_id}" \
            --data-urlencode "domainname=${zone_name}")

        # Accept both 1000 (deleted) and 2201 (no record to remove).
        if echo "$delete_response" | grep -qE '"code":(1000|2201)'; then
            continue
        fi

        echo "[cleanup] Warning: Excedo delete for recordid=${record_id} returned non-success, continuing (idempotent)" >&2
        echo "[cleanup] Response: $delete_response" >&2
    done <<EOF
$record_ids
EOF

    echo "[cleanup] Cleanup complete for $fqdn" >&2
    return 0
}

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

SESSION_TOKEN=$(authenticate) || exit 1

case "$MODE" in
    deploy)
        deploy_record "$FQDN" "$VALIDATION" "$SESSION_TOKEN"
        ;;
    cleanup)
        cleanup_record "$FQDN" "$SESSION_TOKEN" "$VALIDATION"
        ;;
    *)
        echo "Usage: $0 [deploy|cleanup]" >&2
        exit 1
        ;;
esac
