# DONET Installation Summary

**Choose your installation method:**

## 🎯 For Most Users: Quick Install (30 seconds)

```bash
git clone https://github.com/donet/network-analyzer.git && cd network-analyzer && ./install.sh
```

**Or one-liner:**
```bash
curl -sSL https://raw.githubusercontent.com/donet/network-analyzer/main/install.sh | bash
```

This automatically detects your OS (Linux/macOS) and installs everything.

---

## 📦 By Platform

| Platform | Single Command | Notes |
|----------|---------------|-------|
| **Ubuntu/Debian** | `sudo apt install ./donet_1.0.0_all.deb` | Download .deb from releases |
| **RHEL/Fedora/CentOS** | `sudo rpm -ivh donet-1.0.0-1.noarch.rpm` | Download RPM from releases |
| **macOS** | `brew install donet/tap/donet` | Coming soon to Homebrew |
| **Any (Docker)** | `sudo docker run --rm --network host --privileged donet/network-analyzer:latest -i eth0` | Pull from Docker Hub |
| **Any (pip)** | `pip3 install donet-network-analyzer` | When published to PyPI |
| **Any (source)** | `git clone ... && pip3 install -e .` | Always works, latest code |

---

## 🐳 Docker (Easiest, No Install)

```bash
# Pull and run in one line
sudo docker run --rm --network host --privileged donet/network-analyzer:latest --help

# Or use docker-compose
git clone https://github.com/donet/network-analyzer.git && cd network-analyzer
sudo docker-compose up
```

**Advantages:**
- No Python installation needed
- Isolated environment
- Easy to update: `docker pull donet/network-analyzer:latest`

---

## 🔧 Build from Source (Development)

```bash
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
make install  # Uses pip install -e .
```

Or manually:
```bash
pip3 install -r requirements.txt
python3 cli.py --help
```

---

## 📋 Installation Checklist

- [ ] Dependencies installed (Python 3.8+, libpcap)
- [ ] `donet` command in PATH
- [ ] Configuration at `~/.donet/config.yaml`
- [ ] Can run `donet --help` without errors
- [ ] Can list interfaces: `donet --list-interfaces`
- [ ] Tests pass: `pytest tests/ -v`

---

## 🆘 Need Help?

1. **Read INSTALL.md** - Detailed platform-specific instructions
2. **Run test script:** `./test-install.sh` - Diagnoses issues
3. **Check README.md** - Usage examples
4. **Open an issue:** https://github.com/donet/network-analyzer/issues

---

## 🎉 After Installation

```bash
# 1. Verify
donet --version

# 2. See interfaces
donet --list-interfaces

# 3. Test capture (use your interface)
sudo donet -i en0 -c 10

# 4. Generate traffic in another terminal
curl http://example.com

# 5. View report
donet -i en0 -c 1000 -o report.html
```

**That's it! You're ready to analyze network traffic.** 🛡️
