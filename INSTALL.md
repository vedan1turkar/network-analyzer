# DONET Installation Guide

Complete guide to installing DONET Network Analyzer on various platforms.

## Table of Contents

1. [Quick Install (Universal)](#quick-install-universal)
2. [Package Managers](#package-managers)
   - [pip (Python)](#pip-python)
   - [APT (Ubuntu/Debian)](#apt-ubuntudebian)
   - [DNF/YUM (RHEL/Fedora/CentOS)](#dnyum-rhelfedora)
   - [Homebrew (macOS)](#homebrew-macos)
3. [Container Deployment](#container-deployment)
   - [Docker](#docker)
   - [Docker Compose](#docker-compose)
4. [Manual Installation](#manual-installation)
5. [Platform-Specific Notes](#platform-specific-notes)
6. [Post-Installation](#post-installation)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

---

## Quick Install (Universal)

The fastest way to get DONET running on any supported system:

```bash
# Clone and run installer
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
./install.sh
```

**Or one-liner:**
```bash
curl -sSL https://raw.githubusercontent.com/donet/network-analyzer/main/install.sh | bash
```

This script:
- Detects your OS (Linux/macOS)
- Installs system dependencies (Python, libpcap)
- Installs Python packages via pip
- Sets up configuration in `~/.donet/`
- Adds `donet` to your PATH

---

## Package Managers

### pip (Python)

**Prerequisites:** Python 3.8+, pip

```bash
# From PyPI (when published to PyPI)
pip3 install donet-network-analyzer

# From source (current)
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
pip3 install -e .
```

**With sudo (system-wide):**
```bash
sudo pip3 install -e .
```

**For user only (no sudo):**
```bash
pip3 install --user -e .
```

**Verify:**
```bash
donet --version
```

---

### APT (Ubuntu/Debian)

**Method 1: Direct .deb download**

```bash
# Download latest .deb from releases page
wget https://github.com/donet/network-analyzer/releases/download/v1.0.0/donet_1.0.0_all.deb

# Install (dependencies auto-resolved)
sudo apt-get update
sudo apt-get install -y ./donet_1.0.0_all.deb
# Or: sudo dpkg -i donet_1.0.0_all.deb && sudo apt-get install -f
```

**Method 2: Add our APT repository (coming soon)**

```bash
# Add GPG key
curl -fsSL https://apt.donet.example.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/donet-archive-keyring.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/donet-archive-keyring.gpg] https://apt.donet.example.com stable main" | sudo tee /etc/apt/sources.list.d/donet.list

# Install
sudo apt update
sudo apt install donet
```

**Uninstall:**
```bash
sudo apt remove donet
sudo apt autoremove
```

---

### DNF/YUM (RHEL/Fedora/CentOS)

**Method 1: Direct RPM download**

```bash
# Download RPM
wget https://github.com/donet/network-analyzer/releases/download/v1.0.0/donet-1.0.0-1.noarch.rpm

# Install
sudo rpm -ivh donet-1.0.0-1.noarch.rpm
# Or with dnf (handles dependencies):
sudo dnf install ./donet-1.0.0-1.noarch.rpm
```

**Method 2: Add repository (coming soon)**

```bash
# Create repo file
sudo tee /etc/yum.repos.d/donet.repo <<EOF
[donet]
name=DONET Network Analyzer
baseurl=https://rpm.donet.example.com/stable
enabled=1
gpgcheck=1
gpgkey=https://rpm.donet.example.com/gpg
EOF

# Install
sudo dnf install donet
# or: sudo yum install donet
```

**Uninstall:**
```bash
sudo rpm -e donet
```

---

### Homebrew (macOS)

**Coming soon to Homebrew core:**

```bash
brew install donet
```

**Until then, install from source:**

```bash
# Install dependencies
brew install python libpcap

# Clone and install
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
pip3 install -e .
```

**Uninstall:**
```bash
pip3 uninstall donet-network-analyzer
```

---

## Container Deployment

### Docker

**Pull pre-built image:**
```bash
docker pull donet/network-analyzer:latest
```

**Run:**
```bash
# Show help
sudo docker run --rm --network host --privileged donet/network-analyzer:latest --help

# Capture on interface (replace eth0)
sudo docker run --rm --network host --privileged donet/network-analyzer:latest -i eth0 --live

# Save report
sudo docker run --rm --network host --privileged \
  -v $(pwd)/reports:/reports \
  donet/network-analyzer:latest -i eth0 -c 1000 -o /reports/report.html
```

**Build yourself:**
```bash
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
docker build -t donet/network-analyzer:local .
```

**Important Docker notes:**
- `--network host` - Required to capture packets (shared network namespace)
- `--privileged` - Required for raw socket access
- On Docker Desktop (Mac/Windows), host networking may need special configuration

---

### Docker Compose

**Quick start:**
```bash
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
sudo docker-compose up
```

This starts DONET in live mode automatically.

**Customize:** Edit `docker-compose.yml` to change interface, filters, etc.

**Stop:**
```bash
sudo docker-compose down
```

---

## Manual Installation

Full control over installation:

```bash
# 1. Clone repository
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer

# 2. Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip3 install -r requirements.txt

# 4. Test
pytest tests/ -v

# 5. Run
python3 cli.py --help
sudo python3 cli.py -i en0
```

---

## Platform-Specific Notes

### Linux

**Ubuntu/Debian:**
```bash
sudo apt-get install python3 python3-pip python3-dev libpcap-dev
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install python3 python3-pip python3-devel libpcap-devel
# Or on newer Fedora:
sudo dnf install python3 python3-pip python3-devel libpcap-devel
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip libpcap
```

### macOS

```bash
# Install Xcode command line tools (if not installed)
xcode-select --install

# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python libpcap

# Install DONET
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
pip3 install -e .
```

**Note:** On macOS, interfaces are named `en0`, `en1`, `lo0`, etc. Use `ifconfig` to list.

### Windows

**Via WSL2 (Recommended):**
1. Install WSL2: `wsl --install`
2. Install Ubuntu from Microsoft Store
3. Follow Linux instructions inside WSL2
4. Capture from Windows interfaces using WSL2 integration

**Native Windows (Experimental):**
1. Install Python 3.8+ from python.org
2. Install Npcap: https://npcap.com/#download (check "WinPcap API-compatible Mode")
3. Install Visual C++ Build Tools
4. Install DONET:
   ```cmd
   pip install -r requirements.txt
   python cli.py --help
   ```
5. Run Command Prompt as Administrator

---

## Post-Installation

### Configuration

Default config location: `~/.donet/config.yaml`

```bash
# Edit config
nano ~/.donet/config.yaml

# Or copy example
cp config.example.yaml ~/.donet/config.yaml
```

**Key settings:**
- `threat_detection.suspicious_ports` - Ports to flag
- `threat_detection.port_scan_threshold` - Sensitivity
- `performance.packet_sampling` - Performance tuning
- `logging.file` - Enable file logging

### Permissions

**Linux/macOS:** Raw packet capture requires capabilities:

```bash
# Option 1: Use sudo (simplest)
sudo donet -i eth0

# Option 2: Set capabilities (no sudo needed)
sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
# Now you can run: donet -i eth0

# Option 3: Add user to specific groups (varies by OS)
sudo usermod -a -G netdev $USER
# Log out and back in
```

**Windows:** Always run as Administrator.

### PATH Issues

If `donet` command not found:

```bash
# Add to PATH (bash/zsh)
export PATH="$HOME/.local/bin:$PATH"

# Permanent: add to ~/.bashrc or ~/.zshrc
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

---

## Verification

Test your installation:

```bash
# 1. Check version
donet --version
# Expected: DONET 1.0.0

# 2. List interfaces
donet --list-interfaces
# Expected: List of network interfaces

# 3. Run unit tests
pytest tests/ -v
# Expected: All 12 tests pass

# 4. Quick capture test (loopback)
sudo donet -i lo0 -c 10
# Expected: Capture completes, shows statistics

# 5. Generate traffic and verify detection
# In one terminal: sudo donet -i lo0 --live
# In another: curl http://example.com
# Expected: HTTP packets shown with SAFE/INFO level
```

---

## Troubleshooting

### "Permission denied" or "Operation not permitted"

**Cause:** Not running as root or missing capabilities.

**Fix:**
```bash
# Use sudo
sudo donet -i eth0

# Or set capabilities (Linux)
sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
```

### "Interface not found" or "No such device"

**Cause:** Interface name incorrect or doesn't exist.

**Fix:**
```bash
# List available interfaces
donet --list-interfaces
# or: ip link show (Linux)
# or: ifconfig (macOS)

# Use correct name from list
sudo donet -i en0  # macOS
sudo donet -i eth0  # Linux
```

### "ModuleNotFoundError: No module named 'scapy'"

**Cause:** Dependencies not installed.

**Fix:**
```bash
pip3 install -r requirements.txt
# Or reinstall: pip3 install --upgrade scapy
```

### "libpcap not found" during scapy install

**Cause:** Missing system library.

**Fix:**
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# RHEL/CentOS/Fedora
sudo yum install libpcap-devel

# macOS
brew install libpcap
```

### High CPU usage

**Cause:** Processing every packet on high-throughput network.

**Fix:**
1. Enable packet sampling in config:
   ```yaml
   performance:
     packet_sampling: 5  # Process 1/5 packets
   ```
2. Use BPF filter to reduce volume:
   ```bash
   donet -i eth0 -f "tcp port 80"
   ```
3. Disable verbose mode
4. Use `--count` to limit duration

### No packets captured

**Check:**
1. Interface is up: `ip link show` or `ifconfig`
2. Not in monitor mode (WiFi) - use managed mode
3. Filter isn't excluding all traffic
4. Try loopback: `sudo donet -i lo0`

### Docker: "permission denied while trying to connect to the Docker daemon"

**Fix:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### macOS: "Operation not permitted" even with sudo

**Cause:** macOS requires additional entitlements for packet capture.

**Fix:**
```bash
# Install with explicit permissions
sudo python3 -m pip install -e .
# Or use: sudo donet -i en0
```

If still failing, check System Preferences → Security & Privacy → Privacy → Full Disk Access (add Terminal).

---

## Uninstall

### pip installation
```bash
pip3 uninstall donet-network-analyzer
# Or if installed with -e:
pip3 uninstall donet
```

### APT/Debian
```bash
sudo apt remove donet
sudo apt autoremove
```

### RPM
```bash
sudo rpm -e donet
```

### Homebrew
```bash
brew uninstall donet
```

### Docker
```bash
docker rmi donet/network-analyzer:latest
```

### Manual
```bash
rm -rf ~/.donet
rm -f $(which donet)  # If symlinked
# Also remove from ~/.local/bin/ if installed there
```

---

## Getting Help

- **Documentation:** [README.md](README.md)
- **Issues:** https://github.com/donet/network-analyzer/issues
- **Configuration:** `donet --help` and `~/.donet/config.yaml`

---

**Ready to use!** 🎉
