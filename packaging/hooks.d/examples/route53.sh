#!/bin/sh
#
# AWS Route53 DNS Hook - DNS01 Challenge Management
#
# This hook script manages DNS01 ACME challenges for AWS Route53.
# It creates and deletes TXT records required for certificate validation.
#
# ENVIRONMENT VARIABLES (from acme-gateway or certbot):
#   CERTBOT_DOMAIN        - The domain being validated (e.g., example.com)
#   CERTBOT_VALIDATION    - The validation string for the TXT record
#   ACME_GATEWAY_DOMAIN   - Alternative domain variable (acme-gateway format)
#   ACME_GATEWAY_TOKEN    - Alternative validation variable (acme-gateway format)
#   AWS_PROFILE           - AWS profile name (optional, uses default if not set)
#   AWS_REGION            - AWS region (default: us-east-1)
#   ROUTE53_ZONE_ID       - Route53 hosted zone ID (required for multi-zone setup)
#
# AWS CREDENTIALS:
#   Use standard AWS credential chain:
#   - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
#   - IAM role attached to EC2 instance or container
#   - ~/.aws/credentials file
#   - ~/.aws/config file
#
# USAGE:
#   # Deploy mode (create TXT record)
#   ./route53.sh deploy
#   CERTBOT_DOMAIN=example.com CERTBOT_VALIDATION=xyz123 ./route53.sh
#
#   # Cleanup mode (delete TXT record)
#   ./route53.sh cleanup
#   CERTBOT_DOMAIN=example.com CERTBOT_VALIDATION=xyz123 ./route53.sh cleanup
#
# REQUIRED IAM PERMISSIONS:
#   {
#     "Version": "2012-10-17",
#     "Statement": [
#       {
#         "Effect": "Allow",
#         "Action": [
#           "route53:ListHostedZonesByName",
#           "route53:ChangeResourceRecordSets",
#           "route53:GetChange"
#         ],
#         "Resource": "*"
#       }
#     ]
#   }
#

set -e

# Configuration
AWS_PROFILE="${AWS_PROFILE:-}"
AWS_REGION="${AWS_REGION:-us-east-1}"
ROUTE53_ZONE_ID="${ROUTE53_ZONE_ID:-}"
RECORD_TTL="${RECORD_TTL:-60}"

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

log_message() {
    echo "[route53] [$MODE] $1"
}

log_message "Processing domain: $DOMAIN"
log_message "Challenge record: $CHALLENGE_RECORD"
log_message "AWS region: $AWS_REGION"

# Build AWS CLI command prefix
AWS_CMD="aws route53"
if [ -n "$AWS_PROFILE" ]; then
    AWS_CMD="$AWS_CMD --profile $AWS_PROFILE"
fi

# Find the hosted zone ID if not provided
if [ -z "$ROUTE53_ZONE_ID" ]; then
    log_message "Looking up hosted zone for: $DOMAIN"
    ZONE_LOOKUP=$($AWS_CMD list-hosted-zones-by-name --dns-name "$DOMAIN" --region "$AWS_REGION" --query 'HostedZones[0].Id' --output text 2>/dev/null || true)
    
    if [ -z "$ZONE_LOOKUP" ] || [ "$ZONE_LOOKUP" = "None" ]; then
        echo "ERROR: Could not find hosted zone for $DOMAIN" >&2
        exit 1
    fi
    
    # Extract zone ID from ARN (format: /hostedzone/ZXXXXX)
    ROUTE53_ZONE_ID=$(echo "$ZONE_LOOKUP" | sed 's|/hostedzone/||')
fi

log_message "Using hosted zone ID: $ROUTE53_ZONE_ID"

# Create JSON batch change request
create_change_batch() {
    local action=$1
    local ttl=$2
    
    if [ "$action" = "UPSERT" ]; then
        cat <<EOF
{
  "Changes": [
    {
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "$CHALLENGE_RECORD",
        "Type": "TXT",
        "TTL": $ttl,
        "ResourceRecords": [
          {
            "Value": "\"$VALIDATION\""
          }
        ]
      }
    }
  ]
}
EOF
    else
        cat <<EOF
{
  "Changes": [
    {
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "$CHALLENGE_RECORD",
        "Type": "TXT",
        "TTL": $ttl,
        "ResourceRecords": [
          {
            "Value": "\"$VALIDATION\""
          }
        ]
      }
    }
  ]
}
EOF
    fi
}

# Execute based on mode
case "$MODE" in
    deploy)
        log_message "Creating TXT record..."
        BATCH=$(create_change_batch "UPSERT" "$RECORD_TTL")
        CHANGE_ID=$($AWS_CMD change-resource-record-sets \
            --hosted-zone-id "$ROUTE53_ZONE_ID" \
            --region "$AWS_REGION" \
            --change-batch "$BATCH" \
            --query 'ChangeInfo.Id' \
            --output text)
        
        if [ -z "$CHANGE_ID" ] || [ "$CHANGE_ID" = "None" ]; then
            echo "ERROR: Failed to create TXT record" >&2
            exit 1
        fi
        
        log_message "Successfully created TXT record: $CHALLENGE_RECORD"
        log_message "Change ID: $CHANGE_ID"
        ;;
    cleanup)
        log_message "Deleting TXT record..."
        BATCH=$(create_change_batch "DELETE" "$RECORD_TTL")
        CHANGE_ID=$($AWS_CMD change-resource-record-sets \
            --hosted-zone-id "$ROUTE53_ZONE_ID" \
            --region "$AWS_REGION" \
            --change-batch "$BATCH" \
            --query 'ChangeInfo.Id' \
            --output text 2>/dev/null || true)
        
        if [ -z "$CHANGE_ID" ] || [ "$CHANGE_ID" = "None" ]; then
            log_message "TXT record not found or already deleted (this is OK)"
        else
            log_message "Successfully deleted TXT record: $CHALLENGE_RECORD"
            log_message "Change ID: $CHANGE_ID"
        fi
        ;;
    *)
        echo "ERROR: Invalid mode '$MODE'. Use 'deploy' or 'cleanup'" >&2
        exit 1
        ;;
esac

log_message "Operation completed successfully"
exit 0
