#!/usr/bin/env bash
# Installation script for Vitorius Firewall on Fedora Linux
# Created by Vitorius
# License: MIT

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APPS_DIR="$HOME/.local/share/applications"
ICONS_BASE="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$HOME/Desktop"

echo "=== Installing Vitorius Firewall ==="

# Terminate any running instances and clear stale sockets before upgrade
pkill -f "vitorius.*main.py" 2>/dev/null || true
rm -f "$XDG_RUNTIME_DIR/vitorius-firewall.sock" /tmp/vitorius-firewall-*.sock 2>/dev/null || true

mkdir -p "$APPS_DIR"
mkdir -p "$ICONS_BASE/scalable/apps"

# Clean up any legacy duplicate desktop entries to ensure only one launcher exists
rm -f "$APPS_DIR/vitorius-firewall.desktop"
rm -f "$DESKTOP_DIR/com.vitorius.firewall.desktop" 2>/dev/null || true

# 1. Install scalable SVG icons under standard application IDs
cp "$SCRIPT_DIR/data/vitorius-firewall.svg" "$ICONS_BASE/scalable/apps/vitorius-firewall.svg" 2>/dev/null || true
cp "$SCRIPT_DIR/data/vitorius-firewall.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall.svg" 2>/dev/null || true
cp "$SCRIPT_DIR/data/vitorius-firewall-panic.svg" "$ICONS_BASE/scalable/apps/vitorius-firewall-panic.svg" 2>/dev/null || true
cp "$SCRIPT_DIR/data/vitorius-firewall-panic.svg" "$ICONS_BASE/scalable/apps/com.vitorius.firewall-panic.svg" 2>/dev/null || true

# 2. Install pre-rendered PNG icons across all standard desktop resolutions
for size in 16 24 32 48 64 128 256 512; do
    mkdir -p "$ICONS_BASE/${size}x${size}/apps"
    if [ -f "$SCRIPT_DIR/data/icons/${size}x${size}/com.vitorius.firewall.png" ]; then
        cp "$SCRIPT_DIR/data/icons/${size}x${size}/com.vitorius.firewall.png" "$ICONS_BASE/${size}x${size}/apps/com.vitorius.firewall.png" 2>/dev/null || true
        cp "$SCRIPT_DIR/data/icons/${size}x${size}/vitorius-firewall.png" "$ICONS_BASE/${size}x${size}/apps/vitorius-firewall.png" 2>/dev/null || true
    fi
done

# Prepare desktop entry
DESKTOP_FILE_CONTENT="[Desktop Entry]
Version=1.30
Name=Vitorius Firewall
GenericName=Corporate Firewall Manager
Comment=Corporate-grade Windows-style firewall management with security profiles and live monitor
Exec=\"$SCRIPT_DIR/run.sh\"
Path=$SCRIPT_DIR
Icon=com.vitorius.firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=true
StartupWMClass=com.vitorius.firewall
Keywords=firewall;security;network;fedora;rules;ports;monitor;corporate;
X-KDE-SubstituteUID=false
"

# 3. Install to Application Menu (single entry)
# Determine current version from this script
CURRENT_VERSION="1.30"
# Check for existing desktop entry and compare versions
if [ -f "${APPS_DIR}/com.vitorius.firewall.desktop" ]; then
    INSTALLED_VERSION=$(grep -E '^Version=' "${APPS_DIR}/com.vitorius.firewall.desktop" | cut -d= -f2)
    if [ -n "$INSTALLED_VERSION" ]; then
        # Compare versions using sort -V (semantic version aware)
        if [ "$INSTALLED_VERSION" = "$CURRENT_VERSION" ]; then
            echo "✔ Already installed at version $CURRENT_VERSION – refreshing installation"
            echo "$DESKTOP_FILE_CONTENT" > "${APPS_DIR}/com.vitorius.firewall.desktop"
            chmod +x "${APPS_DIR}/com.vitorius.firewall.desktop"
        elif [ "$(printf "%s\n%s" "$INSTALLED_VERSION" "$CURRENT_VERSION" | sort -V | head -n1)" = "$CURRENT_VERSION" ]; then
            echo "ℹ Installed version ($INSTALLED_VERSION) is newer than package ($CURRENT_VERSION)"
        else
            echo "⬆ Updating from version $INSTALLED_VERSION to $CURRENT_VERSION"
            echo "$DESKTOP_FILE_CONTENT" > "${APPS_DIR}/com.vitorius.firewall.desktop"
            chmod +x "${APPS_DIR}/com.vitorius.firewall.desktop"
        fi
    else
        # No version info, install fresh
        echo "$DESKTOP_FILE_CONTENT" > "${APPS_DIR}/com.vitorius.firewall.desktop"
        chmod +x "${APPS_DIR}/com.vitorius.firewall.desktop"
    fi
else
    # No existing entry – install fresh
    echo "$DESKTOP_FILE_CONTENT" > "${APPS_DIR}/com.vitorius.firewall.desktop"
    chmod +x "${APPS_DIR}/com.vitorius.firewall.desktop"
fi

# 4. Install to Desktop folder if it exists – create only if not already present or newer
if [ -d "$DESKTOP_DIR" ]; then
    DESKTOP_FILE_PATH="$DESKTOP_DIR/vitorius-firewall.desktop"
    if [ -f "$DESKTOP_FILE_PATH" ]; then
        INSTALLED_VER=$(grep -E '^Version=' "$DESKTOP_FILE_PATH" | cut -d= -f2)
        if [ -n "$INSTALLED_VER" ]; then
            if [ "$INSTALLED_VER" = "$CURRENT_VERSION" ]; then
                echo "✔ Desktop shortcut already at version $CURRENT_VERSION – refreshing"
                echo "$DESKTOP_FILE_CONTENT" > "$DESKTOP_FILE_PATH"
                chmod +x "$DESKTOP_FILE_PATH"
            elif [ "$(printf "%s\n%s" "$INSTALLED_VER" "$CURRENT_VERSION" | sort -V | head -n1)" = "$CURRENT_VERSION" ]; then
                echo "ℹ Desktop shortcut has newer version ($INSTALLED_VER) – skipping"
            else
                echo "⬆ Updating desktop shortcut from $INSTALLED_VER to $CURRENT_VERSION"
                echo "$DESKTOP_FILE_CONTENT" > "$DESKTOP_FILE_PATH"
                chmod +x "$DESKTOP_FILE_PATH"
            fi
        else
            echo "$DESKTOP_FILE_CONTENT" > "$DESKTOP_FILE_PATH"
            chmod +x "$DESKTOP_FILE_PATH"
        fi
    else
        echo "$DESKTOP_FILE_CONTENT" > "$DESKTOP_FILE_PATH"
        chmod +x "$DESKTOP_FILE_PATH"
    fi
    # Mark trusted in KDE Plasma / GNOME
    if command -v gio >/dev/null 2>&1; then
        gio set -t string "$DESKTOP_FILE_PATH" metadata::trusted true 2>/dev/null || true
    fi
    echo "✓ Desktop shortcut ensured at $DESKTOP_DIR"
fi

# 4b. Sync autostart desktop entry if enabled
AUTOSTART_DIR="$HOME/.config/autostart"
CONFIG_FILE="$HOME/.config/vitorius-firewall/config.json"
if [ -f "$CONFIG_FILE" ] && grep -q '"autostart": true' "$CONFIG_FILE" 2>/dev/null; then
    mkdir -p "$AUTOSTART_DIR"
    cat <<EOF > "$AUTOSTART_DIR/vitorius-firewall.desktop"
[Desktop Entry]
Version=1.30
Name=Vitorius Firewall
GenericName=Corporate Firewall Manager
Comment=Corporate-grade Windows-style firewall management with security profiles and live monitor
Exec="$SCRIPT_DIR/run.sh" --minimized
Path=$SCRIPT_DIR
Icon=com.vitorius.firewall
Terminal=false
Type=Application
Categories=System;Security;Settings;Network;
StartupNotify=false
StartupWMClass=com.vitorius.firewall
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
X-KDE-autostart-phase=2
EOF
    chmod +x "$AUTOSTART_DIR/vitorius-firewall.desktop"
    command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload 2>/dev/null || true
    echo "✓ Autostart entry synced with systemd"
fi

# 5. Update icon cache
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "$ICONS_BASE" 2>/dev/null || true
fi

# 6. Update desktop database
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi

# 7. Update KDE sycoca cache if running on KDE Plasma
if command -v kbuildsycoca6 >/dev/null 2>&1; then
    kbuildsycoca6 2>/dev/null || true
elif command -v kbuildsycoca5 >/dev/null 2>&1; then
    kbuildsycoca5 2>/dev/null || true
fi

echo "✓ Vitorius Firewall installed successfully!"
echo "Launching Vitorius Firewall now..."
echo ""

# Automatically launch the application in background
"$SCRIPT_DIR/run.sh" &
disown

