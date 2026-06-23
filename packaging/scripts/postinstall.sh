#!/bin/sh
# Debian postinstall script for acme-gateway.
# Called by dpkg after files are placed on disk.
set -e

# Create service user if it does not exist.
if ! id -u acme-gateway > /dev/null 2>&1; then
    useradd \
        --system \
        --shell /usr/sbin/nologin \
        --home-dir /var/lib/acme-gateway \
        --no-create-home \
        --comment "acme-gateway service account" \
        acme-gateway
fi

# Ensure ownership of runtime directories.
chown acme-gateway:acme-gateway /var/lib/acme-gateway
chmod 0750 /var/lib/acme-gateway

# Notify about DNS hook configuration.
cat << 'EOF'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 acme-gateway: DNS Hook Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 For dns-01 challenge validation, you must configure DNS hook scripts:

   • Copy an example from: /etc/acme-gateway/hooks.d/examples/
   • Customize for your DNS provider
   • Deploy to: /etc/acme-gateway/hooks.d/

 Available examples:
   • dns_present.sh           — Template for publishing dns-01 records
   • dns_cleanup.sh           — Template for removing dns-01 records
   • route53.sh               — AWS Route53 integration
   • cloudflare.sh            — Cloudflare DNS integration
   • bind-nsupdate.sh         — BIND with nsupdate integration
   • excedo.sh                — Excedo DNS API integration

 Documentation: https://github.com/danieldonoghue/acme-gateway

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EOF

# Reload systemd and enable the service.
if command -v systemctl > /dev/null 2>&1 && systemctl is-system-running --quiet 2>/dev/null; then
    systemctl daemon-reload
    systemctl enable acme-gateway.service || true
fi
