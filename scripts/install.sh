#!/bin/bash
#
# DONET Network Analyzer - Universal Installer
# Supports: Ubuntu/Debian, RHEL/CentOS/Fedora, macOS
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for system-wide install
if [ "$EUID" -eq 0 ]; then
    SUDO=""
    INSTALL_PREFIX="/usr/local"
else
    SUDO="sudo"
    INSTALL_PREFIX="$HOME/.local"
fi

log_info "Starting DONET Network Analyzer installation..."

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        DISTRO="unknown"
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    DISTRO="macos"
else
    log_error "Unsupported OS: $OSTYPE"
    exit 1
fi

log_info "Detected OS: $OS ($DISTRO)"

# Install system dependencies
log_info "Installing system dependencies..."

if [ "$OS" = "linux" ]; then
    if [ "$DISTRO" = "debian" ]; then
        $SUDO apt-get update
        $SUDO apt-get install -y python3 python3-pip python3-dev libpcap-dev
    elif [ "$DISTRO" = "rhel" ]; then
        $SUDO yum install -y python3 python3-pip python3-devel libpcap-devel
    else
        log_warn "Unknown Linux distro. Please install python3, pip, and libpcap-dev manually."
    fi
elif [ "$OS" = "macos" ]; then
    if ! command -v brew &> /dev/null; then
        log_warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python libpcap
fi

# Install Python dependencies
log_info "Installing Python dependencies..."
pip3 install --upgrade pip setuptools wheel

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Install in development mode (editable)
if [ "$EUID" -eq 0 ]; then
    pip3 install -e .
else
    pip3 install --user -e .
fi

# Create config directory
log_info "Setting up configuration..."
CONFIG_DIR="$HOME/.donet"
mkdir -p "$CONFIG_DIR"

# Copy example config if no config exists
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp config.example.yaml "$CONFIG_DIR/config.yaml"
    log_info "Default configuration copied to $CONFIG_DIR/config.yaml"
    log_warn "Edit $CONFIG_DIR/config.yaml to customize settings"
fi

# Create reports directory
mkdir -p "$SCRIPT_DIR/reports"

# Success message
echo ""
echo -e "${GREEN}✓${NC} DONET Network Analyzer installed successfully!"
echo ""
echo "Usage:"
echo "  donet --help                    # Show help"
echo "  donet --list-interfaces         # List network interfaces"
echo "  sudo donet -i <interface>       # Start capture"
echo ""
echo "Examples:"
echo "  sudo donet -i en0               # Capture on macOS"
echo "  sudo donet -i eth0              # Capture on Linux"
echo "  sudo donet -i eth0 --live       # Live monitoring"
echo "  sudo donet -i eth0 -c 1000 -o report.html"
echo ""
echo "Configuration: $CONFIG_DIR/config.yaml"
echo "Reports will be saved to: $SCRIPT_DIR/reports"
echo ""
echo -e "${YELLOW}Note:${NC} Packet capture requires root privileges (sudo)."
echo ""
