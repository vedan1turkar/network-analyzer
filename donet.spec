Name:           donet
Version:        1.0.0
Release:        1%{?dist}
Summary:        Real-time packet threat detection with emoji indicators
License:        MIT
URL:            https://github.com/donet/network-analyzer
Source0:        https://github.com/donet/network-analyzer/archive/refs/tags/v1.0.0.tar.gz

BuildArch:      noarch
Requires:       python3, python3-pip, libpcap

%description
DONET (Network Analyzer) is a lightweight network intrusion detection system (IDS)
that captures and analyzes network packets in real-time, detecting potential
threats using signature-based and anomaly-based detection methods.

Features:
- IPv4 and IPv6 support
- Real-time threat detection with emoji indicators
- Multiple report formats (TXT, JSON, HTML)
- Configurable via YAML
- Port scan, ARP spoofing, and anomaly detection
- Live monitoring mode

%prep
%setup -q

%install
# Install Python package
python3 -m pip install --root %{buildroot} --no-cache-dir -e .

# Create config directory
mkdir -p %{buildroot}/etc/donet
cp config.example.yaml %{buildroot}/etc/donet/config.yaml

# Create logs directory
mkdir -p %{buildroot}/var/log/donet

%post
echo "=== DONET Network Analyzer ==="
echo ""
echo "Configuration: /etc/donet/config.yaml"
echo "Reports: /var/log/donet"
echo ""
echo "Quick start:"
echo "  donet --list-interfaces"
echo "  sudo donet -i <interface>"
echo ""

%files
%license LICENSE
%doc README.md
%config(noreplace) /etc/donet/config.yaml
%dir /var/log/donet
/usr/local/bin/donet
/usr/local/share/donet/*

%changelog
* Thu Apr 27 2024 DONET Team <donet@example.com> - 1.0.0-1
- Initial package release
