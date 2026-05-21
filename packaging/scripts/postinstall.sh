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

# Reload systemd and enable the service.
if command -v systemctl > /dev/null 2>&1 && systemctl is-system-running --quiet 2>/dev/null; then
    systemctl daemon-reload
    systemctl enable acme-gateway.service || true
fi
