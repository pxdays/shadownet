#!/bin/bash
# ShadowNet - Termux (Android) Installer
# Run: bash install_termux.sh

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║    ShadowNet - Termux Installer      ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# Update packages
echo -e "${BLUE}[*] Updating Termux packages...${NC}"
pkg update -y
pkg upgrade -y

# Install dependencies
echo -e "${BLUE}[*] Installing build dependencies...${NC}"
pkg install -y python clang binutils libffi openssl git curl

# Install pip deps
echo -e "${BLUE}[*] Installing Python packages...${NC}"
pip install --upgrade pip
pip install dnspython

# Make executable
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/shadownet.py"

# Create symlink in Termux bin
ln -sf "$SCRIPT_DIR/shadownet.py" "$PREFIX/bin/shadownet"
ln -sf "$SCRIPT_DIR/shadownet.py" "$PREFIX/bin/sn"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ShadowNet ready on Android!          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}shadownet interactive${NC}     - Launch interactive mode"
echo -e "  ${CYAN}shadownet scan <target>${NC}   - Full scan"
echo ""
echo -e "  ${BLUE}Tip:${NC} For network scanning on Android,"
echo -e "  you may need to grant Termux storage permissions:"
echo -e "  ${CYAN}termux-setup-storage${NC}"
echo ""

