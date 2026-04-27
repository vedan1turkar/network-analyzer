# DONET - Network Analyzer

**Real-time packet threat detection with emoji indicators**

DONET is a lightweight network intrusion detection system (IDS) that captures and analyzes network packets in real-time, detecting potential threats using signature-based and anomaly-based detection methods.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

### Threat Detection
- **Signature-based detection**: Known attack patterns (SQL injection, XSS, path traversal)
- **Port-based detection**: Suspicious service ports (SSH brute force, RDP, VNC, etc.)
- **Port scan detection**: Identifies scanning activity from single sources
- **Protocol anomaly detection**: NULL scans, XMAS scans, ICMP floods
- **ARP spoofing detection**: Time-window based MAC address change detection
- **Baseline anomaly detection**: Packet rate spikes, excessive port diversity

### Network Support
- **IPv4 & IPv6**: Full support for both protocols
- **Multiple protocols**: TCP, UDP, ICMP, ARP, DNS
- **BPF filtering**: Use standard Berkeley Packet Filter syntax
- **Live monitoring**: Real-time output with colorized threat levels

### Reporting
- **Multiple formats**: TXT, JSON, HTML reports
- **Emoji indicators**: Visual threat level representation
- **Verbose mode**: Detailed packet information
- **Statistics summary**: Threat breakdown by level and type

### Configuration
- **YAML config**: Customize all detection parameters
- **Logging**: Console and rotating file logging
- **Performance**: Packet sampling for high-throughput networks

---

## 🚀 Installation (Single Command)

### **Option 1: Quick Install (All Platforms) - RECOMMENDED**
One-command universal installer:
```bash
# Clone and install automatically
git clone https://github.com/donet/network-analyzer.git && cd network-analyzer && ./install.sh

# Or one-liner (curl):
curl -sSL https://raw.githubusercontent.com/donet/network-analyzer/main/install.sh | bash

# Or one-liner (wget):
wget -qO- https://raw.githubusercontent.com/donet/network-analyzer/main/install.sh | bash
```

This installs DONET system-wide with all dependencies and creates a `donet` command.

---

### **Option 2: pip (Python Package)**
```bash
# Install from PyPI (WHen Published)
pip3 install donet-network-analyzer

# Or from source
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
pip3 install -e .
```

**Single command after cloning:**
```bash
pip3 install -e . && donet --help
```

---

### **Option 3: System Package Managers**

#### **Ubuntu/Debian**
```bash
# Download and install .deb package
wget https://github.com/donet/network-analyzer/releases/download/v1.0.0/donet_1.0.0_all.deb
sudo dpkg -i donet_1.0.0_all.deb
# Dependencies will be installed automatically
```

Or add our repository (coming soon):
```bash
echo "deb https://apt.donet.example.com stable main" | sudo tee /etc/apt/sources.list.d/donet.list
curl -fsSL https://apt.donet.example.com/gpg | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/donet.gpg
sudo apt update && sudo apt install donet
```

#### **RHEL/CentOS/Fedora**
```bash
# Download and install RPM
wget https://github.com/donet/network-analyzer/releases/download/v1.0.0/donet-1.0.0-1.noarch.rpm
sudo rpm -ivh donet-1.0.0-1.noarch.rpm
```

Or enable our repository (coming soon):
```bash
sudo dnf config-manager --add-repo https://rpm.donet.example.com/donet.repo
sudo dnf install donet
```

#### **macOS (Homebrew)**
```bash
# Install via Homebrew (coming soon)
brew install donet/tap/donet

# Or from source
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
pip3 install -e .
```

---

### **Option 4: Docker (Easiest, No Install)**
```bash
# Pull pre-built image
docker pull donet/network-analyzer:latest

# Run (requires host network access)
sudo docker run --rm --network host --privileged donet/network-analyzer:latest --help

# Start interactive capture
sudo docker run --rm --network host --privileged donet/network-analyzer:latest -i eth0 --live
```

Or use Docker Compose:
```bash
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer
sudo docker-compose up
```

---

### **Option 5: Manual (Full Control)**
```bash
# 1. Clone repository
git clone https://github.com/donet/network-analyzer.git
cd network-analyzer

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Run directly
python3 cli.py --help
sudo python3 cli.py -i en0
```

---

## Prerequisites

- **Python 3.8+** (if not using Docker/system packages)
- **Root/administrator privileges** - Required for raw packet capture
- **Network interface** - Any active NIC (ethernet, WiFi, etc.)

### System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get install python3 python3-pip python3-dev libpcap-dev
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install python3 python3-pip python3-devel libpcap-devel
```

**macOS:**
```bash
brew install python libpcap
```

**Windows:**
- Install [Npcap](https://npcap.com/) (select "WinPcap API-compatible Mode")
- Install Python 3.8+ from python.org
- Run Command Prompt as Administrator

---

## Quick Verification

After installation, verify it works:

```bash
# Check installation
donet --version

# List interfaces
donet --list-interfaces

# Run tests
pytest tests/ -v

# All should work! ✅
```

---

## Quick Start

### Basic Capture
```bash
# Capture on default interface
sudo python cli.py

# Capture on specific interface
sudo python cli.py -i eth0

# Capture with BPF filter (HTTP traffic only)
sudo python cli.py -i eth0 -f "tcp port 80"

# Capture limited number of packets
sudo python cli.py -i eth0 -c 100
```

### Live Monitoring
```bash
# Live mode with compact output
sudo python cli.py -i eth0 --live

# Live mode with verbose output
sudo python cli.py -i eth0 --live -v
```

### Show All Packets
```bash
# Include safe packets in output
sudo python cli.py -i eth0 --show-safe
```

### Save Report
```bash
# Save as text
sudo python cli.py -i eth0 -c 1000 -o report.txt

# Save as JSON
sudo python cli.py -i eth0 -c 1000 -o report.json

# Save as HTML
sudo python cli.py -i eth0 -c 1000 -o report.html
```

### List Interfaces
```bash
python cli.py --list-interfaces
```

---

## Configuration

DONET supports YAML configuration files. Default locations (in order):
1. `~/.donet/config.yaml` (user config)
2. `/etc/donet/config.yaml` (system config)
3. `./config.yaml` (current directory)
4. Specified via `--config` flag

### Example Configuration
```bash
# Use custom config
sudo python cli.py --config /path/to/myconfig.yaml
```

See [`config.example.yaml`](config.example.yaml) for all available options.

### Key Configuration Sections

#### Threat Detection
```yaml
threat_detection:
  suspicious_ports:  # Ports to flag
    22: {name: "SSH", level: "MEDIUM"}
    3389: {name: "RDP", level: "HIGH"}

  malicious_patterns:  # Payload regex patterns
    - pattern: "(?i)(sqlmap|nmap)"
      level: "HIGH"

  port_scan_threshold: 10  # Ports before flagging scan
  arp_time_window: 60      # ARP spoofing time window (seconds)
```

#### Logging
```yaml
logging:
  level: "INFO"        # DEBUG, INFO, WARNING, ERROR
  file: "donet.log"    # null = console only
  max_bytes: 10485760  # 10MB per file
  backup_count: 5      # Rotated files to keep
```

#### Performance
```yaml
performance:
  packet_sampling: 1    # Process every Nth packet (1=all)
  max_tracker_entries: 1000  # Memory limit for trackers
```

---

## Output Format

### Standard Output
```
============================================================
  DONET - Packet Threat Detection
  Version 1.0.0
============================================================

  Configuration:
   Interface: eth0
   Filter: none
   Verbose: False
   Show safe: False

🚨 [CRITICAL] ARP spoofing detected!
   Packet: 192.168.1.100 -> 192.168.1.1 [ARP]
   Threat Score: 100/100
   • ARP spoofing detected! IP changed MAC...

⚠️  [HIGH] Suspicious port detected
   Packet: 192.168.1.200:54321 -> 192.168.1.50:3389 [TCP]
   Threat Score: 50/100
   • Suspicious port 3389 (RDP) detected
```

### Live Mode
```
Time     Level      Source               Destination        Protocol Info
----------------------------------------------------------------------------------------------------
14:30:15 🚨 CRITICAL 192.168.1.100:12345  192.168.1.1:80    🔗 TCP  ARP spoofing detected!
14:30:16 ⚠️  HIGH     192.168.1.200:54321  192.168.1.50:3389 🔐 TCP  Suspicious port
```

### Statistics
```
============================================================
  CAPTURE STATISTICS
============================================================

⏱️  Duration: 125.43 seconds
📊 Total packets analyzed: 15420
🚨 Threats detected: 47

  Threat Level Breakdown:
   🚨 CRITICAL: 3
   ⚠️  HIGH: 12
   ⚡ MEDIUM: 18
   ℹ️  LOW: 14

  Threat Types:
   • Suspicious Port: 22
   • Malicious Pattern: 15
   • Port Scan: 5
   • ARP Spoofing: 3
   • NULL Scan: 2
============================================================
```

---

## Threat Levels

| Level | Score | Meaning | Action |
|-------|-------|---------|--------|
| 🚨 CRITICAL | 100+ | Immediate threat (ARP spoofing, severe attacks) | Investigate immediately |
| ⚠️ HIGH | 50-99 | High risk (suspicious ports, scans, exploits) | Investigate urgently |
| ⚡ MEDIUM | 25-49 | Medium risk (potential reconnaissance) | Monitor closely |
| ℹ️ LOW | 10-24 | Low risk (informational) | Log for review |
| ✅ SAFE | 0-9 | No threat detected | None |

---

## Architecture

```
┌─────────────────┐
│   CLI (cli.py)  │  ← User interface, argument parsing
└────────┬────────┘
         │
         ▼
┌─────────────────────┐
│  PacketCapture      │  ← Scapy-based packet capture
│  (packet_capture.py)│    - Interface selection
└────────┬────────────┘    - BPF filtering
         │                 - Packet parsing (IPv4/IPv6)
         ▼
┌─────────────────────┐
│  ThreatAnalyzer     │  ← Core analysis engine
│  (threat_analyzer.py)│    - Signature matching
└────────┬────────────┘    - Anomaly detection
         │                 - Scoring & correlation
         ▼
┌─────────────────────┐
│  Reporter           │  ← Output formatting
│  (reporter.py)      │    - Colorized console
└────────┬────────────┘    - File reports (TXT/JSON/HTML)
         │
         ▼
    [Output]
```

---

## Development

### Running Tests
```bash
# Install dev dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=threat_analyzer --cov-report=html
```

### Project Structure
```
network_analyzer/
├── __init__.py           # Package metadata
├── cli.py                # Main entry point
├── packet_capture.py     # Packet capture & parsing
├── threat_analyzer.py    # Threat detection engine
├── reporter.py           # Output formatting
├── config.py             # Configuration management
├── requirements.txt      # Dependencies
├── pyproject.toml        # Build configuration
├── config.example.yaml   # Sample configuration
├── README.md            # This file
└── tests/
    ├── __init__.py
    └── test_threat_analyzer.py  # Unit tests
```

---

## Security & Legal

### Legal Use Only
- Only capture traffic on networks you own or have explicit authorization to monitor
- Packet capture may expose sensitive data (passwords, personal information)
- Comply with local privacy laws (e.g., GDPR, CCPA)
- Use in test environments or with explicit consent

### Required Privileges
Raw socket capture requires root/administrator:
```bash
sudo python cli.py ...
```

On Linux, you can set capabilities to avoid sudo:
```bash
sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
```

---

## Performance Tips

### High-Throughput Networks
- Use packet sampling: `packet_sampling: 5` in config (process 1/5 packets)
- Apply BPF filters to reduce captured volume
- Use `--count` to limit capture duration
- Disable verbose mode for better performance

### Memory Management
- Trackers auto-clean when exceeding `max_tracker_entries`
- Restart long-running captures periodically
- Monitor memory usage with `--live` mode

---

## Troubleshooting

### "Permission denied" error
Run with sudo/administrator privileges.

### "Interface not found"
List available interfaces:
```bash
python cli.py --list-interfaces
```

### No packets captured
- Check interface is up: `ip link show`
- Verify filter syntax (if using `-f`)
- Try without filter first

### High CPU usage
- Enable packet sampling in config
- Reduce capture count or use timeout
- Disable verbose mode

### Missing IPv6 packets
Ensure your system and interface support IPv6. Check with:
```bash
ip -6 addr show
```

---

## Contributing

Contributions welcome! Areas for improvement:
- Additional threat signatures
- Machine learning anomaly detection
- Web dashboard / REST API
- Database backend (historical analysis)
- Performance optimizations
- Unit test coverage

---

## License

MIT License - See LICENSE file for details.

---

## Acknowledgments

- **Scapy** - Packet manipulation library
- **colorama** - Cross-platform colored terminal text
- **PyYAML** - YAML parsing

---

## Support

For issues, questions, or feature requests, please open a GitHub issue.

**Project**: DONET Network Analyzer  
**Version**: 1.0.0  
**Status**: Active Development
