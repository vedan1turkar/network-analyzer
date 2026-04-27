#!/bin/bash
#
# DONET Quick Install - One-liner friendly
# Usage: curl -sSL https://donet.example.com/install.sh | bash
# Or: wget -qO- https://donet.example.com/install.sh | bash
#

set -e

# Configuration
REPO_URL="https://github.com/donet/network-analyzer.git"
INSTALL_DIR="${HOME}/.donet"
BIN_DIR="${HOME}/.local/bin"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== DONET Network Analyzer Quick Install ===${NC}"

# Check prerequisites
if ! command -v git &> /dev/null; then
    echo "Installing git..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            sudo apt-get update && sudo apt-get install -y git
        else
            sudo yum install -y git
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install git
    fi
fi

# Clone repository
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Cloning DONET repository..."
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
else
    echo "Updating existing installation..."
    cd "$INSTALL_DIR" && git pull
fi

# Run main installer
cd "$INSTALL_DIR"
chmod +x install.sh
./install.sh

# Add to PATH if needed
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo -e "${YELLOW}Add to PATH:${NC}"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    echo "  (Add to ~/.bashrc or ~/.zshrc to make permanent)"
fi

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo "Run 'donet --help' to get started."
