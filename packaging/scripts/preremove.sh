#!/bin/sh
# Debian pre-remove script for acme-gateway.
# Called by dpkg before files are removed from disk.
set -e

if command -v systemctl > /dev/null 2>&1; then
    systemctl stop  acme-gateway.service || true
    systemctl disable acme-gateway.service || true
fi
