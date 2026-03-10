#!/bin/bash
# Download and update YARA rules for yara_scanner.py
# Sources:
#   - Neo23x0/signature-base: APT attribution rules
#   - YARAHQ/yara-forge: 5000+ rules from 45+ repos (Core ruleset)
#
# Usage:
#   bash Tools/ghidra-headless/setup_yara_rules.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES_DIR="$SCRIPT_DIR/yara-rules"
TEMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

echo "=== YARA Rules Setup ==="
echo "Rules directory: $RULES_DIR"
mkdir -p "$RULES_DIR"

# -------------------------------------------------------
# 1. Neo23x0/signature-base
# -------------------------------------------------------
echo ""
echo "[1/2] Downloading Neo23x0/signature-base..."
SIG_BASE_DIR="$RULES_DIR/signature-base"

if [ -d "$SIG_BASE_DIR/.git" ]; then
    echo "  Updating existing clone..."
    git -C "$SIG_BASE_DIR" pull --ff-only 2>&1 | sed 's/^/  /'
else
    echo "  Cloning repository..."
    rm -rf "$SIG_BASE_DIR"
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git "$SIG_BASE_DIR" 2>&1 | sed 's/^/  /'
fi

SIG_COUNT=$(find "$SIG_BASE_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l | tr -d ' ')
echo "  Rules: $SIG_COUNT files"

# -------------------------------------------------------
# 2. YARAHQ/yara-forge (Core ruleset)
# -------------------------------------------------------
echo ""
echo "[2/2] Downloading YARAHQ/yara-forge Core ruleset..."
FORGE_DIR="$RULES_DIR/yara-forge"
mkdir -p "$FORGE_DIR"

FORGE_URL="https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"
FORGE_ZIP="$TEMP_DIR/yara-forge-core.zip"

echo "  Downloading from: $FORGE_URL"
if command -v curl &>/dev/null; then
    curl -sL -o "$FORGE_ZIP" "$FORGE_URL"
elif command -v wget &>/dev/null; then
    wget -q -O "$FORGE_ZIP" "$FORGE_URL"
else
    echo "  Error: curl or wget required" >&2
    exit 1
fi

echo "  Extracting..."
# Clean old files before extracting
rm -rf "$FORGE_DIR"/*
if command -v unzip &>/dev/null; then
    unzip -qo "$FORGE_ZIP" -d "$FORGE_DIR"
else
    python3 -c "import zipfile; zipfile.ZipFile('$FORGE_ZIP').extractall('$FORGE_DIR')"
fi

FORGE_COUNT=$(find "$FORGE_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l | tr -d ' ')
echo "  Rules: $FORGE_COUNT files"

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo ""
TOTAL=$(find "$RULES_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l | tr -d ' ')
echo "=== Setup Complete ==="
echo "Total rule files: $TOTAL"
echo "Rules directory: $RULES_DIR"
