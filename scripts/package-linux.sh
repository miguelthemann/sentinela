#!/usr/bin/env bash
set -e

BIN_PATH="$1"
TARGET_NAME="$2"
ASSET_NAME="$3"

if [ -z "$BIN_PATH" ] || [ -z "$TARGET_NAME" ] || [ -z "$ASSET_NAME" ]; then
    echo "Uso: $0 <caminho-binario> <target> <asset-name>"
    exit 1
fi

VERSION="0.3.0"

calc_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file"
    else
        shasum -a 256 "$file"
    fi
}

# 1. Empacota Tarball (.tar.gz)
mkdir -p dist
cp "$BIN_PATH" dist/sentinela
cp install.sh dist/
cp README.md dist/
cp LICENSE dist/
chmod +x dist/sentinela dist/install.sh

tar -czf "${ASSET_NAME}.tar.gz" -C dist sentinela install.sh README.md LICENSE
calc_sha256 "${ASSET_NAME}.tar.gz" > "${ASSET_NAME}.tar.gz.sha256"

# Se não for Linux (ex.: macOS), conclui após gerar o tarball
if [ "$(uname -s)" != "Linux" ]; then
    exit 0
fi

# 2. Empacota Debian (.deb)
DEB_ARCH="amd64"
if [ "$TARGET_NAME" = "aarch64-unknown-linux-gnu" ]; then
    DEB_ARCH="arm64"
fi

DEB_ROOT="sentinela_deb_pkg"
rm -rf "$DEB_ROOT"
mkdir -p "${DEB_ROOT}/DEBIAN"
mkdir -p "${DEB_ROOT}/usr/local/bin"
mkdir -p "${DEB_ROOT}/usr/share/doc/sentinela"

cp "$BIN_PATH" "${DEB_ROOT}/usr/local/bin/sentinela"
chmod 755 "${DEB_ROOT}/usr/local/bin/sentinela"
cp README.md LICENSE "${DEB_ROOT}/usr/share/doc/sentinela/"

cat << 'EOF' > "${DEB_ROOT}/DEBIAN/control"
Package: sentinela
Version: 0.3.0
Section: utils
Priority: optional
Architecture: DEB_ARCH_PLACEHOLDER
Maintainer: Salvador Pontes <123838416+teizinh@users.noreply.github.com>
Description: Sentinela - Honeypot & Network Intrusion Detection System
 Sistema leve de deteção de intrusões (NIDS) e armadilhas honeypot em Rust.
EOF
sed -i "s/DEB_ARCH_PLACEHOLDER/${DEB_ARCH}/" "${DEB_ROOT}/DEBIAN/control"

cat << 'EOF' > "${DEB_ROOT}/DEBIAN/postinst"
#!/bin/sh
set -e
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw+eip /usr/local/bin/sentinela 2>/dev/null || true
fi
EOF
chmod 755 "${DEB_ROOT}/DEBIAN/postinst"

if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build "${DEB_ROOT}" "${ASSET_NAME}.deb"
    calc_sha256 "${ASSET_NAME}.deb" > "${ASSET_NAME}.deb.sha256"
fi
rm -rf "$DEB_ROOT"

# 3. Empacota RPM (.rpm) para x86_64 se alien estiver disponivel
if [ "$TARGET_NAME" = "x86_64-unknown-linux-gnu" ] && [ -f "${ASSET_NAME}.deb" ]; then
    if command -v alien >/dev/null 2>&1; then
        alien --to-rpm --scripts "${ASSET_NAME}.deb"
        mv sentinela-*.rpm "${ASSET_NAME}.rpm" 2>/dev/null || true
        if [ -f "${ASSET_NAME}.rpm" ]; then
            calc_sha256 "${ASSET_NAME}.rpm" > "${ASSET_NAME}.rpm.sha256"
        fi
    fi
fi
