#!/usr/bin/env bash
# Sentinel SIEM — macOS .pkg installer builder
#
# Prerequisites:
#   - macOS with Xcode Command Line Tools
#   - dist/Sentinel.app produced by PyInstaller (run build.py first)
#   - (optional) CODE_SIGN_IDENTITY and INSTALLER_SIGN_IDENTITY env vars
#     for notarization (required for distribution outside the Mac App Store)
#
# Usage (run from repo root):
#   bash installer/macos/build-pkg.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_NAME="Sentinel"
APP_BUNDLE="${REPO_ROOT}/dist/${APP_NAME}.app"
PKG_ID="com.nebula.sentinel"
VERSION="1.0.0"
OUTPUT_DIR="${REPO_ROOT}/dist"
STAGING_ROOT="${REPO_ROOT}/dist/_pkg_staging"
SCRIPTS_DIR="${REPO_ROOT}/installer/macos/scripts"

echo "═══ macOS .pkg build ═══"

# ── Validate inputs ───────────────────────────────────────────────────────────
if [ ! -d "$APP_BUNDLE" ]; then
    echo "ERROR: $APP_BUNDLE not found. Run 'python installer/build.py --skip-package' first."
    exit 1
fi

# ── Staging layout ────────────────────────────────────────────────────────────
rm -rf "$STAGING_ROOT"
mkdir -p "${STAGING_ROOT}/root/Applications"
mkdir -p "${STAGING_ROOT}/root/Library/LaunchAgents"
mkdir -p "${STAGING_ROOT}/root/var/lib/sentinel"
mkdir -p "${STAGING_ROOT}/scripts"

# Copy .app bundle to Applications
cp -R "$APP_BUNDLE" "${STAGING_ROOT}/root/Applications/"

# LaunchAgent plist (auto-start at login)
cat > "${STAGING_ROOT}/root/Library/LaunchAgents/com.nebula.sentinel.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nebula.sentinel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Sentinel.app/Contents/MacOS/sentinel</string>
        <string>--headless</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/sentinel/launcher.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/sentinel/launcher.log</string>
    <key>WorkingDirectory</key>
    <string>/var/lib/sentinel</string>
</dict>
</plist>
PLIST

# ── Post-install script ───────────────────────────────────────────────────────
cat > "${STAGING_ROOT}/scripts/postinstall" << 'SCRIPT'
#!/usr/bin/env bash
set -e

# Create data and log directories
mkdir -p /var/lib/sentinel /var/log/sentinel
chmod 755 /var/lib/sentinel /var/log/sentinel

# Load the LaunchAgent
if [ -f /Library/LaunchAgents/com.nebula.sentinel.plist ]; then
    launchctl load -w /Library/LaunchAgents/com.nebula.sentinel.plist 2>/dev/null || true
fi

# Run first-time setup wizard
if [ ! -f /var/lib/sentinel/.env ]; then
    /Applications/Sentinel.app/Contents/MacOS/sentinel --setup &
fi

exit 0
SCRIPT
chmod +x "${STAGING_ROOT}/scripts/postinstall"

# Pre-remove script
cat > "${STAGING_ROOT}/scripts/preinstall" << 'SCRIPT'
#!/usr/bin/env bash
# Stop running instance before upgrade
launchctl unload -w /Library/LaunchAgents/com.nebula.sentinel.plist 2>/dev/null || true
exit 0
SCRIPT
chmod +x "${STAGING_ROOT}/scripts/preinstall"

# ── Build component package ───────────────────────────────────────────────────
COMPONENT_PKG="${OUTPUT_DIR}/${APP_NAME}-component.pkg"

pkgbuild \
    --root "${STAGING_ROOT}/root" \
    --scripts "${STAGING_ROOT}/scripts" \
    --identifier "${PKG_ID}" \
    --version "${VERSION}" \
    --install-location "/" \
    "$COMPONENT_PKG"

echo "  Component package: $COMPONENT_PKG"

# ── Build distribution package ────────────────────────────────────────────────
DIST_XML="${STAGING_ROOT}/distribution.xml"

cat > "$DIST_XML" << XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Sentinel SIEM ${VERSION}</title>
    <organization>com.nebula</organization>
    <domains enable_localSystem="true"/>
    <options require-scripts="true" customize="allow" allow-external-scripts="no"/>
    <welcome file="welcome.html" mime-type="text/html"/>
    <readme  file="readme.html"  mime-type="text/html"/>
    <license file="license.html" mime-type="text/html"/>
    <background file="background.png" mime-type="image/png" alignment="bottomleft" scaling="none"/>
    <choices-outline>
        <line choice="default"/>
    </choices-outline>
    <choice id="default" visible="false">
        <pkg-ref id="${PKG_ID}"/>
    </choice>
    <pkg-ref id="${PKG_ID}" version="${VERSION}" auth="root">${APP_NAME}-component.pkg</pkg-ref>
</installer-gui-script>
XML

FINAL_PKG="${OUTPUT_DIR}/SentinelSetup.pkg"

productbuild \
    --distribution "$DIST_XML" \
    --package-path "$OUTPUT_DIR" \
    --resources "${REPO_ROOT}/installer/macos/resources" \
    "$FINAL_PKG" 2>/dev/null || \
productbuild \
    --distribution "$DIST_XML" \
    --package-path "$OUTPUT_DIR" \
    "$FINAL_PKG"

rm -f "$COMPONENT_PKG"
rm -rf "$STAGING_ROOT"

# ── Code signing (optional) ───────────────────────────────────────────────────
if [ -n "${INSTALLER_SIGN_IDENTITY:-}" ]; then
    echo "  Signing installer with: $INSTALLER_SIGN_IDENTITY"
    productsign \
        --sign "$INSTALLER_SIGN_IDENTITY" \
        "$FINAL_PKG" \
        "${OUTPUT_DIR}/SentinelSetup-signed.pkg"
    mv "${OUTPUT_DIR}/SentinelSetup-signed.pkg" "$FINAL_PKG"
fi

echo "✓ macOS installer: $FINAL_PKG"
