#!/bin/bash
# ShadowNet - Linux / macOS / Termux Installer
# Run: bash install.sh

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════╗"
echo "║         ShadowNet Installer          ║"
echo "╚══════════════════════════════════════╝"
echo -e "${NC}"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[-] Python 3 required. Install it first.${NC}"
    exit 1
fi

PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${BLUE}[*] Python $PY_VER detected${NC}"

# Detect platform
if [ -d "/data/data/com.termux/files/usr" ]; then
    echo -e "${BLUE}[*] Termux (Android) detected${NC}"
    IS_TERMUX=1
    pkg update -y
    pkg install -y python clang libffi openssl
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${BLUE}[*] macOS detected${NC}"
    IS_TERMUX=0
else
    echo -e "${BLUE}[*] Linux detected${NC}"
    IS_TERMUX=0
fi

# Install dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip3 install --upgrade pip 2>/dev/null || true
pip3 install dnspython 2>/dev/null || {
    echo -e "${YELLOW}[!] dnspython install failed (optional - subdomain scanning)${NC}"
}

# Make executable
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR/shadownet.py"

# Create symlink
if [ -d "$HOME/.local/bin" ] && [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
    ln -sf "$SCRIPT_DIR/shadownet.py" "$HOME/.local/bin/shadownet"
    ln -sf "$SCRIPT_DIR/shadownet.py" "$HOME/.local/bin/sn"
    echo -e "${GREEN}[+] Symlinks created in ~/.local/bin${NC}"
elif [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    ln -sf "$SCRIPT_DIR/shadownet.py" "/usr/local/bin/shadownet"
    ln -sf "$SCRIPT_DIR/shadownet.py" "/usr/local/bin/sn"
    echo -e "${GREEN}[+] Symlinks created in /usr/local/bin${NC}"
else
    echo -e "${GREEN}[+] Install complete! Run: python3 $SCRIPT_DIR/shadownet.py${NC}"
    echo -e "${GREEN}    or add to PATH manually${NC}"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ShadowNet installed successfully!   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}shadownet interactive${NC}     - Launch interactive mode"
echo -e "  ${CYAN}shadownet scan <target>${NC}   - Full scan"
echo -e "  ${CYAN}shadownet quick <target>${NC}  - Quick recon"
echo -e "  ${CYAN}shadownet modules${NC}          - List modules"
echo ""

