#!/usr/bin/env bash
# Builds a .deb package for acme-gateway from a pre-compiled binary.
#
# Usage:
#   packaging/build-deb.sh <version> <arch> <debian-major-version>
#
# Arguments:
#   version              SemVer string, e.g. "1.2.3" (no leading "v")
#   arch                 "amd64" or "arm64"
#   debian-major-version "12" or "13"
#
# Inputs:
#   dist/acme-gateway_linux_<arch>   pre-compiled binary (CGO_ENABLED=0)
#   acme-gateway.service             systemd unit file
#   config.yaml.example              example configuration
#   packaging/scripts/               maintainer scripts
#
# Output:
#   dist/acme-gateway_<version>_debian<ver>_<arch>.deb

set -euo pipefail

VERSION="${1:?version argument required}"
ARCH="${2:?arch argument required (amd64|arm64)}"
DEB_VER="${3:?debian major version required (12|13)}"

BINARY="dist/acme-gateway_linux_${ARCH}"
PKG_NAME="acme-gateway_${VERSION}_debian${DEB_VER}_${ARCH}"
BUILD_DIR="dist/.pkg_${PKG_NAME}"

# ── Validate inputs ──────────────────────────────────────────────────────────
if [[ "${ARCH}" != "amd64" && "${ARCH}" != "arm64" ]]; then
    echo "Error: arch must be amd64 or arm64, got '${ARCH}'" >&2
    exit 1
fi
if [[ "${DEB_VER}" != "12" && "${DEB_VER}" != "13" ]]; then
    echo "Error: debian version must be 12 or 13, got '${DEB_VER}'" >&2
    exit 1
fi
if [[ ! -f "${BINARY}" ]]; then
    echo "Error: binary not found: ${BINARY}" >&2
    exit 1
fi

# ── Build directory ──────────────────────────────────────────────────────────
rm -rf "${BUILD_DIR}"
mkdir -p \
    "${BUILD_DIR}/DEBIAN" \
    "${BUILD_DIR}/usr/local/bin" \
    "${BUILD_DIR}/lib/systemd/system" \
    "${BUILD_DIR}/etc/acme-gateway" \
    "${BUILD_DIR}/var/lib/acme-gateway"

# ── Install files ─────────────────────────────────────────────────────────────
install -m 0755 "${BINARY}"            "${BUILD_DIR}/usr/local/bin/acme-gateway"
install -m 0644 acme-gateway.service   "${BUILD_DIR}/lib/systemd/system/acme-gateway.service"
install -m 0644 config.yaml.example    "${BUILD_DIR}/etc/acme-gateway/config.yaml.example"

# ── DEBIAN/conffiles ─────────────────────────────────────────────────────────
echo "/etc/acme-gateway/config.yaml.example" > "${BUILD_DIR}/DEBIAN/conffiles"

# ── DEBIAN/control ───────────────────────────────────────────────────────────
cat > "${BUILD_DIR}/DEBIAN/control" << EOF
Package: acme-gateway
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Daniel Donoghue <maintainer@example.com>
Section: net
Priority: optional
Depends: systemd
Recommends: ca-certificates
Description: ACMEv2 gateway — multi-upstream certificate routing proxy
 Routes certificate requests from ACME clients (Certbot, Lego, acme.sh) to
 multiple upstream certificate authorities based on configurable routing rules.
 Supports profile-based routing, EAB injection, and JWS re-origination.
 .
 Targets Debian ${DEB_VER}.
Homepage: https://github.com/danieldonoghue/acme-gateway
EOF

# ── DEBIAN/md5sums ────────────────────────────────────────────────────────────
(cd "${BUILD_DIR}" && find usr etc lib -type f | LC_ALL=C sort | xargs md5sum > DEBIAN/md5sums)

# ── Maintainer scripts ────────────────────────────────────────────────────────
install -m 0755 packaging/scripts/postinstall.sh "${BUILD_DIR}/DEBIAN/postinst"
install -m 0755 packaging/scripts/preremove.sh   "${BUILD_DIR}/DEBIAN/prerm"
install -m 0755 packaging/scripts/postremove.sh  "${BUILD_DIR}/DEBIAN/postrm"

# ── Build package ─────────────────────────────────────────────────────────────
dpkg-deb --build --root-owner-group "${BUILD_DIR}" "dist/${PKG_NAME}.deb"

# ── Cleanup ───────────────────────────────────────────────────────────────────
rm -rf "${BUILD_DIR}"

echo "Built: dist/${PKG_NAME}.deb"
