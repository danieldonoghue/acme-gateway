#!/bin/sh
# Debian post-remove script for acme-gateway.
# Called by dpkg after files are removed from disk.
# $1 == "purge" when dpkg --purge is used.
set -e

if command -v systemctl > /dev/null 2>&1; then
    systemctl daemon-reload || true
fi

# On purge, remove data and config directories.
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/acme-gateway
    rm -rf /etc/acme-gateway
    # Remove service user.
    if id -u acme-gateway > /dev/null 2>&1; then
        userdel acme-gateway || true
    fi
fi
