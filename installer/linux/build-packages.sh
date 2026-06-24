#!/usr/bin/env bash
# Sentinel SIEM — Linux .deb and .rpm builder
#
# Prerequisites:
#   - fpm  (gem install fpm  or  pip install fpm)
#   - dist/sentinel/  produced by PyInstaller (run build.py first)
#   - systemd-based Linux (Debian/Ubuntu for .deb, RHEL/CentOS for .rpm)
#
# Usage (run from repo root):
#   bash installer/linux/build-packages.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION="1.0.0"
BUNDLE_DIR="${REPO_ROOT}/dist/sentinel"
OUTPUT_DIR="${REPO_ROOT}/dist"
STAGING="${REPO_ROOT}/dist/_linux_staging"

echo "═══ Linux package build ═══"

if [ ! -d "$BUNDLE_DIR" ]; then
    echo "ERROR: $BUNDLE_DIR not found. Run 'python installer/build.py --skip-package' first."
    exit 1
fi

if ! command -v fpm &>/dev/null; then
    echo "ERROR: fpm not found. Install with: gem install fpm"
    exit 1
fi

# ── Staging layout ────────────────────────────────────────────────────────────
rm -rf "$STAGING"
mkdir -p "${STAGING}/opt/sentinel"
mkdir -p "${STAGING}/etc/systemd/system"
mkdir -p "${STAGING}/usr/bin"
mkdir -p "${STAGING}/var/lib/sentinel"
mkdir -p "${STAGING}/var/log/sentinel"
mkdir -p "${STAGING}/usr/share/doc/sentinel"

# Copy PyInstaller bundle
cp -r "${BUNDLE_DIR}/." "${STAGING}/opt/sentinel/"

# Symlink main executable to /usr/bin/sentinel
ln -sf /opt/sentinel/sentinel "${STAGING}/usr/bin/sentinel"

# ── systemd service unit ──────────────────────────────────────────────────────
cat > "${STAGING}/etc/systemd/system/sentinel.service" << 'UNIT'
[Unit]
Description=Sentinel SIEM — Hybrid Log Intelligence Platform
Documentation=https://github.com/ThatAIGuyDFW/NebuLog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinel
Group=sentinel
WorkingDirectory=/var/lib/sentinel
ExecStart=/opt/sentinel/sentinel --headless
Restart=on-failure
RestartSec=10
StandardOutput=append:/var/log/sentinel/launcher.log
StandardError=append:/var/log/sentinel/launcher.log

# Hardening
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
# Allow binding privileged ports (514)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

# ── Post-install script ───────────────────────────────────────────────────────
cat > "${REPO_ROOT}/installer/linux/postinst" << 'POSTINST'
#!/bin/bash
set -e

# Create sentinel system user
if ! id -u sentinel &>/dev/null; then
    useradd --system --no-create-home --shell /sbin/nologin sentinel
fi

# Create data and log directories
mkdir -p /var/lib/sentinel /var/log/sentinel
chown -R sentinel:sentinel /var/lib/sentinel /var/log/sentinel
chmod 750 /var/lib/sentinel /var/log/sentinel

# Fix bundle permissions
chown -R sentinel:sentinel /opt/sentinel
chmod +x /opt/sentinel/sentinel

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable sentinel.service || true

echo ""
echo "══════════════════════════════════════════════════"
echo "  Sentinel SIEM installed."
echo ""
echo "  Run first-time setup:"
echo "    sudo -u sentinel sentinel --setup"
echo ""
echo "  Then start the service:"
echo "    sudo systemctl start sentinel"
echo ""
echo "  Dashboard: http://localhost:8000"
echo "══════════════════════════════════════════════════"

exit 0
POSTINST
chmod +x "${REPO_ROOT}/installer/linux/postinst"

# ── Pre-remove script ─────────────────────────────────────────────────────────
cat > "${REPO_ROOT}/installer/linux/postrm" << 'POSTRM'
#!/bin/bash
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop sentinel.service 2>/dev/null || true
    systemctl disable sentinel.service 2>/dev/null || true
    systemctl daemon-reload || true
fi
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/sentinel /var/log/sentinel
fi
exit 0
POSTRM
chmod +x "${REPO_ROOT}/installer/linux/postrm"

# ── Copy systemd unit into staging ───────────────────────────────────────────
# (already written above into staging)

# ── Build .deb ───────────────────────────────────────────────────────────────
echo ""
echo "Building .deb …"
fpm \
    --input-type dir \
    --output-type deb \
    --name sentinel \
    --version "$VERSION" \
    --architecture amd64 \
    --description "Sentinel SIEM — Hybrid SIEM & Log Intelligence Platform by Nebula Networking" \
    --url "https://github.com/ThatAIGuyDFW/NebuLog" \
    --maintainer "Nebula Networking <admin@nebula.local>" \
    --license "Proprietary" \
    --depends "postgresql-client-16" \
    --depends "redis-tools" \
    --after-install "${REPO_ROOT}/installer/linux/postinst" \
    --after-remove "${REPO_ROOT}/installer/linux/postrm" \
    --package "${OUTPUT_DIR}/sentinel_${VERSION}_amd64.deb" \
    --chdir "$STAGING" \
    .

echo "✓ .deb → ${OUTPUT_DIR}/sentinel_${VERSION}_amd64.deb"

# ── Build .rpm ───────────────────────────────────────────────────────────────
echo ""
echo "Building .rpm …"
fpm \
    --input-type dir \
    --output-type rpm \
    --name sentinel \
    --version "$VERSION" \
    --architecture x86_64 \
    --description "Sentinel SIEM — Hybrid SIEM & Log Intelligence Platform by Nebula Networking" \
    --url "https://github.com/ThatAIGuyDFW/NebuLog" \
    --maintainer "Nebula Networking <admin@nebula.local>" \
    --license "Proprietary" \
    --depends "postgresql" \
    --depends "redis" \
    --after-install "${REPO_ROOT}/installer/linux/postinst" \
    --after-remove "${REPO_ROOT}/installer/linux/postrm" \
    --package "${OUTPUT_DIR}/sentinel-${VERSION}-1.x86_64.rpm" \
    --chdir "$STAGING" \
    .

echo "✓ .rpm → ${OUTPUT_DIR}/sentinel-${VERSION}-1.x86_64.rpm"

rm -rf "$STAGING"
echo ""
echo "✅ Linux packages built."
