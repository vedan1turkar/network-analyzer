# DONET Packaging & Distribution Guide

This document describes all available installation methods for DONET Network Analyzer.

## 📦 Available Packages

| Format | Platform | Command | File |
|--------|----------|---------|------|
| **pip** | Any Python | `pip3 install donet-network-analyzer` | PyPI |
| **Deb** | Ubuntu/Debian | `sudo apt install donet_1.0.0_all.deb` | Releases |
| **RPM** | RHEL/Fedora/CentOS | `sudo rpm -ivh donet-*.rpm` | Releases |
| **Docker** | Any with Docker | `docker pull donet/network-analyzer` | Docker Hub |
| **Homebrew** | macOS | `brew install donet/tap/donet` | donet.rb |
| **Source** | Any | `git clone && pip install -e .` | GitHub |

---

## 🚀 Quick Reference

### Fastest Methods

**1. Universal installer (Linux/macOS):**
```bash
curl -sSL https://raw.githubusercontent.com/donet/network-analyzer/main/install.sh | bash
```

**2. Docker (no install, just run):**
```bash
sudo docker run --rm --network host --privileged donet/network-analyzer:latest -i eth0 --live
```

**3. pip (if published):**
```bash
pip3 install donet-network-analyzer && donet --help
```

---

## 📁 Files in This Repository

```
network-analyzer/
├── cli.py                    # Main entry point
├── setup.py                  # pip installation
├── requirements.txt          # Python dependencies
├── pyproject.toml           # Modern Python config
├── Dockerfile               # Docker image
├── docker-compose.yml       # Docker Compose config
├── install.sh               # Universal installer (Linux/macOS)
├── quick-install.sh         # One-liner installer
├── test-install.sh          # Installation verification
├── build-deb.sh             # Build .deb package
├── build-rpm.sh             # Build RPM package
├── donet.rb                 # Homebrew formula
├── donet.spec               # RPM spec file
├── debian/                  # Debian packaging files
│   ├── DEBIAN/
│   │   ├── control         # Package metadata
│   │   └── postinst        # Post-install script
│   └── ...
├── README.md               # Main documentation
├── INSTALL.md              # Detailed install guide
├── PACKAGING.md            # This file
└── config.example.yaml     # Sample configuration
```

---

## 🔨 Building Packages Yourself

### Build .deb (Debian/Ubuntu)
```bash
./build-deb.sh
# Output: donet_1.0.0_all.deb
```

### Build RPM (RHEL/Fedora/CentOS)
```bash
./build-rpm.sh
# Output: donet-1.0.0-1.noarch.rpm
```

### Build Docker Image
```bash
docker build -t donet/network-analyzer:local .
# Or: make docker
```

### Build via pip
```bash
pip3 install build
python3 -m build
# Output: dist/donet_network_analyzer-1.0.0-py3-none-any.whl
```

---

## 🐳 Docker Details

### Images
- **Production:** `donet/network-analyzer:latest`
- **Development:** `donet/network-analyzer:dev`
- **Local build:** `donet/network-analyzer:local`

### Usage
```bash
# Basic
sudo docker run --rm --network host --privileged donet/network-analyzer:latest --help

# Capture with output
sudo docker run --rm \
  --network host \
  --privileged \
  -v $(pwd)/reports:/reports \
  donet/network-analyzer:latest \
  -i eth0 -c 1000 -o /reports/report.html
```

**Why these flags?**
- `--network host` - Share host network stack (needed for packet capture)
- `--privileged` - Grant all capabilities (including CAP_NET_RAW)
- `-v` - Mount volume for reports

---

## 🍎 macOS Installation

### Method 1: Homebrew (when available)
```bash
brew install donet/tap/donet
```

### Method 2: Universal installer
```bash
./install.sh
```

### Method 3: pip
```bash
pip3 install -e .
```

---

## 🐧 Linux Distribution-Specific

### Ubuntu/Debian
```bash
# Quick
sudo apt install ./donet_1.0.0_all.deb

# With repository (future)
sudo apt update && sudo apt install donet
```

### RHEL/CentOS/Fedora
```bash
# Quick
sudo rpm -ivh donet-1.0.0-1.noarch.rpm

# With dnf (better dependency handling)
sudo dnf install ./donet-1.0.0-1.noarch.rpm

# With repository (future)
sudo dnf install donet
```

### Arch Linux (AUR - community maintained)
```bash
yay -S donet
# Or: paru -S donet
```
*(AUR package needs to be created by community)*

---

## 🔄 Updating

### pip
```bash
pip3 install --upgrade donet-network-analyzer
```

### Docker
```bash
docker pull donet/network-analyzer:latest
```

### Debian/Ubuntu
```bash
sudo apt update && sudo apt upgrade donet
```

### RPM
```bash
sudo dnf update donet
# or: sudo yum update donet
```

### Source
```bash
cd network-analyzer
git pull
pip3 install -e . --upgrade
```

---

## 🗑️ Uninstalling

### pip
```bash
pip3 uninstall donet-network-analyzer
```

### Debian/Ubuntu
```bash
sudo apt remove donet
sudo apt autoremove
```

### RPM
```bash
sudo rpm -e donet
```

### Docker
```bash
docker rmi donet/network-analyzer:latest
```

### Source
```bash
pip3 uninstall donet
rm -rf ~/.donet
# Also remove from ~/.local/bin/ if present
```

---

## 📊 Distribution Comparison

| Feature | pip | .deb | .rpm | Docker | Homebrew |
|---------|-----|------|------|--------|----------|
| Auto-deps | ✅ | ✅ | ✅ | ✅ | ✅ |
| System integration | ❌ | ✅ | ✅ | ❌ | ✅ |
| Easy update | ✅ | ✅ | ✅ | ✅ | ✅ |
| No sudo needed | ✅ | ❌ | ❌ | ⚠️¹ | ✅ |
| Isolated | ✅ | ❌ | ❌ | ✅ | ❌ |
| Works on all OS | ✅ | ❌ | ❌ | ✅ | ❌ |

¹ Docker needs sudo for socket unless user in docker group

---

## 🎯 Recommended by Use Case

| Use Case | Recommended Method |
|----------|-------------------|
| **Quick test** | Docker or quick-install.sh |
| **Production server** | .deb / .rpm from releases |
| **Development** | pip install -e . |
| **Multiple machines** | Docker or system package |
| **No root access** | pip --user or Docker |
| **macOS** | Homebrew (when available) or install.sh |
| **Always latest** | git clone + pip install -e . |

---

## 📝 Creating Your Own Package

### For Debian/Ubuntu
```bash
./build-deb.sh
# Creates: donet_1.0.0_all.deb
```

### For RHEL/Fedora/CentOS
```bash
./build-rpm.sh
# Creates: donet-1.0.0-1.noarch.rpm
```

### For Docker
```bash
docker build -t donet/network-analyzer:custom .
```

### For pip
```bash
python3 -m build
# Creates: dist/donet_network_analyzer-1.0.0-py3-none-any.whl
```

---

## 🌐 Future Distribution Channels

- **PyPI** - `pip install donet-network-analyzer` (pending)
- **APT Repository** - `apt install donet` (planned)
- **Docker Hub** - `docker pull donet/network-analyzer` (ready)
- **Homebrew Core** - `brew install donet` (submitted)
- **Snap Store** - `snap install donet` (considering)
- **AUR** - `yay -S donet` (community)

---

## ✅ Verification

After any installation, verify:

```bash
donet --version          # Should print 1.0.0
donet --list-interfaces  # Should show interfaces
pytest tests/ -v         # All tests should pass
```

If issues, run diagnostic:
```bash
./test-install.sh
```

---

**Questions?** See [INSTALL.md](INSTALL.md) for detailed platform instructions.
