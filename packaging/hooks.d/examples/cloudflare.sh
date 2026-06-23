#!/bin/sh
#
# Cloudflare DNS Hook - DNS01 Challenge Management via API
#
# This hook script manages DNS01 ACME challenges for Cloudflare DNS.
# It creates and deletes TXT records required for certificate validation
# using the Cloudflare API.
#
# ENVIRONMENT VARIABLES (from acme-gateway or certbot):
#   CERTBOT_DOMAIN            - The domain being validated (e.g., example.com)
#   CERTBOT_VALIDATION        - The validation string for the TXT record
#   ACME_GATEWAY_DOMAIN       - Alternative domain variable (acme-gateway format)
#   ACME_GATEWAY_TOKEN        - Alternative validation variable (acme-gateway format)
#   CLOUDFLARE_API_TOKEN      - Cloudflare API token (required)
#   CLOUDFLARE_ZONE_ID        - Cloudflare zone ID (optional, auto-lookup if not set)
#   CLOUDFLARE_API_ENDPOINT   - API endpoint (default: https://api.cloudflare.com/client/v4)
#
# CLOUDFLARE SETUP:
#   1. Create API Token at: https://dash.cloudflare.com/profile/api-tokens
#   2. Permissions needed:
#      - Zone / DNS / Edit
#      - Zone / Zone / Read
#   3. Set CLOUDFLARE_API_TOKEN environment variable
#
# USAGE:
#   # Deploy mode (create TXT record)
#   CLOUDFLARE_API_TOKEN=abc123... ./cloudflare.sh deploy
#   CERTBOT_DOMAIN=example.com CERTBOT_VALIDATION=xyz123 ./cloudflare.sh
#
#   # Cleanup mode (delete TXT record)
#   CLOUDFLARE_API_TOKEN=abc123... ./cloudflare.sh cleanup
#   CERTBOT_DOMAIN=example.com CERTBOT_VALIDATION=xyz123 ./cloudflare.sh cleanup
#
# DEPENDENCIES:
#   - curl: HTTP client for API calls
#   - jq: JSON processor (optional, used for better error messages)
#
# ERRORS:
#   - Exit code 1: Missing environment variables or API errors
#   - Exit code 2: Network or curl errors
#

set -e

# Configuration
CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
CLOUDFLARE_ZONE_ID="${CLOUDFLARE_ZONE_ID:-}"
CLOUDFLARE_API_ENDPOINT="${CLOUDFLARE_API_ENDPOINT:-https://api.cloudflare.com/client/v4}"

# Determine mode from script name or first argument
SCRIPT_NAME=$(basename "$0" .sh)
MODE="${1:-}"

if [ -z "$MODE" ]; then
    if echo "$SCRIPT_NAME" | grep -q "cleanup"; then
        MODE="cleanup"
    else
        MODE="deploy"
    fi
fi

# Get domain and validation token from environment
# Try both CERTBOT_ and ACME_GATEWAY_ prefixes
DOMAIN="${CERTBOT_DOMAIN:-${ACME_GATEWAY_DOMAIN:-}}"
VALIDATION="${CERTBOT_VALIDATION:-${ACME_GATEWAY_TOKEN:-}}"

# Validate required inputs
if [ -z "$DOMAIN" ]; then
    echo "ERROR: CERTBOT_DOMAIN or ACME_GATEWAY_DOMAIN not set" >&2
    exit 1
fi

if [ -z "$VALIDATION" ]; then
    echo "ERROR: CERTBOT_VALIDATION or ACME_GATEWAY_TOKEN not set" >&2
    exit 1
fi

if [ -z "$CLOUDFLARE_API_TOKEN" ]; then
    echo "ERROR: CLOUDFLARE_API_TOKEN not set" >&2
    exit 1
fi

# Construct the challenge record name
CHALLENGE_RECORD="_acme-challenge.${DOMAIN}"

log_message() {
    echo "[cloudflare] [$MODE] $1"
}

log_message "Processing domain: $DOMAIN"
log_message "Challenge record: $CHALLENGE_RECORD"
log_message "API endpoint: $CLOUDFLARE_API_ENDPOINT"

# Helper function to make API calls
cloudflare_api() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    local curl_opts="-s -X $method"
    curl_opts="$curl_opts -H 'Authorization: Bearer $CLOUDFLARE_API_TOKEN'"
    curl_opts="$curl_opts -H 'Content-Type: application/json'"
    
    if [ -n "$data" ]; then
        curl_opts="$curl_opts -d '$data'"
    fi
    
    eval "curl $curl_opts '$CLOUDFLARE_API_ENDPOINT$endpoint'"
}

# Extract zone name from domain (for API lookup)
extract_zone_name() {
    local domain=$1
    # Try progressively shorter domain suffixes to find zone
    # e.g., sub.example.com -> example.com
    local parts=$(echo "$domain" | awk -F. '{print NF}')
    
    while [ "$parts" -ge 2 ]; do
        echo "$domain" | awk -F. -v n=$parts '{
            for(i=NF-n+1; i<=NF; i++) {
                if(i>NF-n) printf "."
                printf "%s", $i
            }
        }'
        parts=$((parts - 1))
    done
}

# Find zone ID if not provided
if [ -z "$CLOUDFLARE_ZONE_ID" ]; then
    log_message "Looking up zone ID for: $DOMAIN"
    
    ZONE_NAME="$DOMAIN"
    ZONE_RESPONSE=$(cloudflare_api "GET" "/zones?name=$ZONE_NAME&status=active" "")
    
    # Check if response indicates success and has results
    ZONE_ID=$(echo "$ZONE_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
    
    if [ -z "$ZONE_ID" ]; then
        echo "ERROR: Could not find Cloudflare zone for $DOMAIN" >&2
        echo "Response: $ZONE_RESPONSE" >&2
        exit 1
    fi
    
    CLOUDFLARE_ZONE_ID="$ZONE_ID"
fi

log_message "Using zone ID: $CLOUDFLARE_ZONE_ID"

# Execute based on mode
case "$MODE" in
    deploy)
        log_message "Creating TXT record: $CHALLENGE_RECORD"
        
        # Create DNS record
        RECORD_DATA=$(cat <<EOF
{
  "type": "TXT",
  "name": "$CHALLENGE_RECORD",
  "content": "$VALIDATION",
  "ttl": 120,
  "priority": 10
}
EOF
)
        
        RESPONSE=$(cloudflare_api "POST" "/zones/$CLOUDFLARE_ZONE_ID/dns_records" "$RECORD_DATA")
        
        # Check for success in response
        if echo "$RESPONSE" | grep -q '"success":true'; then
            RECORD_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
            log_message "Successfully created TXT record"
            log_message "Record ID: $RECORD_ID"
        else
            echo "ERROR: Failed to create TXT record" >&2
            echo "Response: $RESPONSE" >&2
            exit 1
        fi
        ;;
    cleanup)
        log_message "Deleting TXT record: $CHALLENGE_RECORD"
        
        # List records to find the one we created
        LIST_RESPONSE=$(cloudflare_api "GET" "/zones/$CLOUDFLARE_ZONE_ID/dns_records?type=TXT&name=$CHALLENGE_RECORD" "")
        
        # Extract record ID from list response
        RECORD_ID=$(echo "$LIST_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
        
        if [ -z "$RECORD_ID" ]; then
            log_message "TXT record not found (may already be deleted)"
        else
            DELETE_RESPONSE=$(cloudflare_api "DELETE" "/zones/$CLOUDFLARE_ZONE_ID/dns_records/$RECORD_ID" "")
            
            if echo "$DELETE_RESPONSE" | grep -q '"success":true'; then
                log_message "Successfully deleted TXT record"
            else
                echo "ERROR: Failed to delete TXT record" >&2
                echo "Response: $DELETE_RESPONSE" >&2
                exit 1
            fi
        fi
        ;;
    *)
        echo "ERROR: Invalid mode '$MODE'. Use 'deploy' or 'cleanup'" >&2
        exit 1
        ;;
esac

log_message "Operation completed successfully"
exit 0
