#!/bin/sh
#
# BIND DNS Hook - DNS01 Challenge Management via nsupdate
#
# This hook script manages DNS01 ACME challenges for BIND DNS servers
# using the nsupdate utility. It adds and removes TXT records required
# for certificate validation.
#
# ENVIRONMENT VARIABLES (from acme-gateway or certbot):
#   CERTBOT_DOMAIN        - The domain being validated (e.g., example.com)
#   CERTBOT_VALIDATION    - The validation string for the TXT record
#   ACME_GATEWAY_DOMAIN   - Alternative domain variable (acme-gateway format)
#   ACME_GATEWAY_TOKEN    - Alternative validation variable (acme-gateway format)
#   DNS_SERVER            - BIND server address (default: localhost)
#   DNS_KEY_FILE          - TSIG key file for authentication (optional)
#   DNS_ZONE              - DNS zone name (auto-detected if not set)
#
# USAGE:
#   # Deploy mode (add TXT record)
#   ./bind-nsupdate.sh deploy
#   CERTBOT_DOMAIN=example.com CERTBOT_VALIDATION=xyz123 ./bind-nsupdate.sh
#
#   # Cleanup mode (remove TXT record)
#   ./bind-nsupdate.sh cleanup
#   CERTBOT_DOMAIN=example.com CERTBOT_VALIDATION=xyz123 ./bind-nsupdate.sh cleanup
#
# CONFIGURATION:
#   Update DNS_SERVER, DNS_KEY_FILE, and DNS_ZONE variables below if needed.
#   For TSIG authentication, set DNS_KEY_FILE to point to your key file.
#
# ERRORS:
#   - Non-zero exit code on missing environment variables
#   - Non-zero exit code on nsupdate command failure
#

set -e

# Configuration
DNS_SERVER="${DNS_SERVER:-localhost}"
DNS_KEY_FILE="${DNS_KEY_FILE:-}"
DNS_ZONE="${DNS_ZONE:-}"
DNS_TTL="${DNS_TTL:-60}"

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

# Construct the challenge record name
CHALLENGE_RECORD="_acme-challenge.${DOMAIN}"

# Determine DNS zone if not explicitly set
if [ -z "$DNS_ZONE" ]; then
    # Simple zone detection: assume zone matches domain or parent
    DNS_ZONE="$DOMAIN"
fi

log_message() {
    echo "[bind-nsupdate] [$MODE] $1"
}

log_message "Processing domain: $DOMAIN"
log_message "Challenge record: $CHALLENGE_RECORD"
log_message "DNS server: $DNS_SERVER"
log_message "DNS zone: $DNS_ZONE"

# Build nsupdate command
if [ -n "$DNS_KEY_FILE" ]; then
    log_message "Using TSIG key file: $DNS_KEY_FILE"
    NSUPDATE_CMD="nsupdate -k $DNS_KEY_FILE"
else
    log_message "Using standard nsupdate (no TSIG)"
    NSUPDATE_CMD="nsupdate"
fi

# Execute nsupdate based on mode
case "$MODE" in
    deploy)
        log_message "Deploying challenge record..."
        $NSUPDATE_CMD <<EOF
server $DNS_SERVER
zone $DNS_ZONE
update add $CHALLENGE_RECORD $DNS_TTL TXT "$VALIDATION"
send
quit
EOF
        if [ $? -eq 0 ]; then
            log_message "Successfully added TXT record: $CHALLENGE_RECORD = $VALIDATION"
        else
            echo "ERROR: Failed to add TXT record" >&2
            exit 1
        fi
        ;;
    cleanup)
        log_message "Cleaning up challenge record..."
        $NSUPDATE_CMD <<EOF
server $DNS_SERVER
zone $DNS_ZONE
update delete $CHALLENGE_RECORD TXT
send
quit
EOF
        if [ $? -eq 0 ]; then
            log_message "Successfully removed TXT record: $CHALLENGE_RECORD"
        else
            echo "ERROR: Failed to remove TXT record" >&2
            exit 1
        fi
        ;;
    *)
        echo "ERROR: Invalid mode '$MODE'. Use 'deploy' or 'cleanup'" >&2
        exit 1
        ;;
esac

log_message "Operation completed successfully"
exit 0
