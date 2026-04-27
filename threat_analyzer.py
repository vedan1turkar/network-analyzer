"""
Threat Analysis Engine - Analyzes packets for potential threats
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)

# Threat level definitions
THREAT_LEVELS = {
    'CRITICAL': {
        'score': 100,
        'emoji': '🚨',
        'color': '\033[91m',  # Red
        'description': 'Critical threat - Immediate action required'
    },
    'HIGH': {
        'score': 50,
        'emoji': '⚠️',
        'color': '\033[93m',  # Yellow
        'description': 'High risk threat - Investigate immediately'
    },
    'MEDIUM': {
        'score': 25,
        'emoji': '⚡',
        'color': '\033[94m',  # Blue
        'description': 'Medium risk - Monitor closely'
    },
    'LOW': {
        'score': 10,
        'emoji': 'ℹ️',
        'color': '\033[96m',  # Cyan
        'description': 'Low risk - Information only'
    },
    'SAFE': {
        'score': 0,
        'emoji': '✅',
        'color': '\033[92m',  # Green
        'description': 'No threat detected'
    }
}

# Known malicious patterns
SUSPICIOUS_PORTS = {
    22: ('SSH', 'MEDIUM'),  # SSH brute force
    23: ('Telnet', 'HIGH'),
    25: ('SMTP', 'MEDIUM'),
    53: ('DNS', 'LOW'),
    69: ('TFTP', 'HIGH'),
    110: ('POP3', 'MEDIUM'),
    135: ('RPC', 'HIGH'),
    139: ('NetBIOS', 'HIGH'),
    143: ('IMAP', 'MEDIUM'),
    161: ('SNMP', 'MEDIUM'),
    389: ('LDAP', 'MEDIUM'),
    445: ('SMB', 'HIGH'),
    1433: ('MSSQL', 'HIGH'),
    3306: ('MySQL', 'MEDIUM'),
    3389: ('RDP', 'HIGH'),
    5900: ('VNC', 'HIGH'),
    8080: ('HTTP-ALT', 'LOW'),
    8443: ('HTTPS-ALT', 'LOW')
}

# Suspicious IP patterns (private ranges are normal, but certain patterns may be suspicious)
SUSPICIOUS_IP_PATTERNS = [
    r'^10\.0\.0\.\d+$',  # Specific private range
    r'^192\.168\.1\.\d+$',
]

# Known malicious User-Agents / payload patterns
MALICIOUS_PATTERNS = [
    (r'(?i)(sqlmap|nmap|nikto|burp|metasploit)', 'HIGH', 'Known scanning tool'),
    (r'(?i)(<script>|javascript:|onload=|onerror=)', 'HIGH', 'XSS pattern'),
    (r'(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table)', 'MEDIUM', 'SQL injection pattern'),
    (r'(?i)(eval\(|exec\(|system\(|passthru\()', 'HIGH', 'Code execution pattern'),
    (r'(?i)(\.\./|\.\.\\|/etc/passwd|/etc/shadow)', 'MEDIUM', 'Path traversal'),
    (r'(?i)(cmd\.exe|powershell|wscript|bitsadmin)', 'HIGH', 'Windows command execution'),
    (r'(?i)(wget\s+http|curl\s+http|ftp\s+get)', 'MEDIUM', 'File download'),
]

# Port scan detection thresholds
PORT_SCAN_THRESHOLD = 10  # Multiple ports from same IP within time window
MAX_TRACKER_ENTRIES = 1000  # Maximum entries to prevent memory leak


class ThreatAnalyzer:
    """Analyzes network packets for threats"""

    # Type annotations for class attributes
    config: Config
    threat_history: list
    port_scan_tracker: dict
    arp_cache: dict
    total_packets_analyzed: int
    suspicious_ports: dict
    malicious_patterns: list
    port_scan_threshold: int
    arp_time_window: int
    max_tracker_entries: int
    baseline_window: int
    baseline_rate_threshold: int
    baseline_port_diversity_threshold: int
    packet_rate_history: list
    port_distribution: dict
    protocol_distribution: dict
    baseline_alert_cooldown: dict
    baseline_cooldown_period: int

    def __init__(self, config: Config = None):
        """
        Initialize threat analyzer

        Args:
            config: Configuration object (uses defaults if None)
        """
        self.config = config or Config()
        self.threat_history = []
        self.port_scan_tracker = {}  # Track (src_ip, dst_ip) -> {'ports': set(), 'first_seen': ts, 'last_seen': ts}
        self.arp_cache = {}  # Track IP -> (MAC, timestamp) tuples for time-window analysis
        self.total_packets_analyzed = 0  # Track all packets analyzed

        # Load configurable values
        self.suspicious_ports = self.config.get('threat_detection', 'suspicious_ports', default={})
        self.malicious_patterns = self.config.get('threat_detection', 'malicious_patterns', default=[])
        self.port_scan_threshold = self.config.get('threat_detection', 'port_scan_threshold', default=10)
        self.arp_time_window = self.config.get('threat_detection', 'arp_time_window', default=60)
        self.max_tracker_entries = self.config.get('performance', 'max_tracker_entries', default=1000)

        # Baseline anomaly detection
        self.baseline_window = self.config.get('threat_detection', 'baseline_window', default=300)
        self.baseline_rate_threshold = self.config.get('threat_detection', 'baseline_rate_threshold', default=100)  # pps
        self.baseline_port_diversity_threshold = self.config.get('threat_detection', 'baseline_port_diversity_threshold', default=20)
        self.packet_rate_history = []  # List of (timestamp, count) for rate calculation
        self.port_distribution = {}  # Track src_ip -> {'ports': set(), 'last_seen': ts}
        self.protocol_distribution = {}  # Track protocol counts over time
        self.baseline_alert_cooldown = {}  # Track (src_ip, threat_type) -> last_alert_timestamp
        self.baseline_cooldown_period = 60  # seconds between repeat alerts for same source/threat

    def analyze_packet(self, packet_info: Dict) -> Dict:
        """
        Analyze a single packet and determine threat level

        Args:
            packet_info: Parsed packet dictionary from PacketCapture.parse_packet()

        Returns:
            Dictionary with threat assessment
        """
        self.total_packets_analyzed += 1
        threat_score = 0
        threats = []
        threat_level = 'SAFE'

        # Check 1: Suspicious ports
        port_threat = self._check_ports(packet_info)
        if port_threat:
            threat_score += port_threat['score']
            threats.append(port_threat)

        # Check 2: Malicious payload patterns
        payload_threat = self._check_payload(packet_info)
        if payload_threat:
            threat_score += payload_threat['score']
            threats.append(payload_threat)

        # Check 3: Port scanning detection
        scan_threat = self._check_port_scan(packet_info)
        if scan_threat:
            threat_score += scan_threat['score']
            threats.append(scan_threat)

        # Check 4: Suspicious protocol behavior
        proto_threat = self._check_protocol_anomalies(packet_info)
        if proto_threat:
            threat_score += proto_threat['score']
            threats.append(proto_threat)

        # Check 5: ARP spoofing detection
        if packet_info.get('protocol') == 'ARP':
            arp_threat = self._check_arp_spoofing(packet_info)
            if arp_threat:
                threat_score += arp_threat['score']
                threats.append(arp_threat)

        # Check 6: Baseline anomaly detection
        baseline_threat = self._check_baseline_anomaly(packet_info)
        if baseline_threat:
            threat_score += baseline_threat['score']
            threats.append(baseline_threat)

        # Determine overall threat level based on score and highest individual threat
        # Prioritize by highest individual threat level first
        highest_threat_level = 'SAFE'
        for threat in threats:
            threat_level_value = THREAT_LEVELS[threat['level']]['score']
            if threat_level_value > THREAT_LEVELS[highest_threat_level]['score']:
                highest_threat_level = threat['level']

        # Then adjust by total score
        if threat_score >= 100 or highest_threat_level == 'CRITICAL':
            threat_level = 'CRITICAL'
        elif threat_score >= 50 or highest_threat_level == 'HIGH':
            threat_level = 'HIGH'
        elif threat_score >= 25 or highest_threat_level == 'MEDIUM':
            threat_level = 'MEDIUM'
        elif threat_score >= 10 or highest_threat_level == 'LOW':
            threat_level = 'LOW'
        else:
            threat_level = 'SAFE'

        result = {
            'threat_level': threat_level,
            'threat_score': threat_score,
            'threats': threats,
            'emoji': THREAT_LEVELS[threat_level]['emoji'],
            'color': THREAT_LEVELS[threat_level]['color'],
            'description': THREAT_LEVELS[threat_level]['description'],
            'timestamp': packet_info.get('timestamp'),
            'packet_summary': self._create_summary(packet_info)
        }

        if threat_level != 'SAFE':
            self.threat_history.append(result)
            logger.warning(f"Threat detected: {threat_level} - {result['packet_summary']}")

        return result

    def _check_ports(self, packet_info: Dict) -> Optional[Dict]:
        """Check for suspicious port usage"""
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')

        if dst_port in self.suspicious_ports:
            port_info = self.suspicious_ports[dst_port]
            port_name = port_info.get('name', 'Unknown')
            level = port_info.get('level', 'MEDIUM')
            score = THREAT_LEVELS[level]['score']
            return {
                'type': 'suspicious_port',
                'score': score,
                'message': f"Suspicious port {dst_port} ({port_name}) detected",
                'level': level
            }
        return None

    def _check_payload(self, packet_info: Dict) -> Optional[Dict]:
        """Check payload for malicious patterns (handles binary data)"""
        payload = packet_info.get('payload')
        if not payload:
            return None

        try:
            # Convert payload to string for regex matching
            if isinstance(payload, str):
                payload_str = payload
            else:
                # Try multiple encodings to handle binary data
                payload_str = None
                for encoding in ['utf-8', 'latin-1', 'ascii']:
                    try:
                        payload_str = payload.decode(encoding, errors='ignore')
                        if payload_str and len(payload_str) > 0:
                            break
                    except (UnicodeDecodeError, AttributeError):
                        continue
                if payload_str is None:
                    # Fallback: represent as hex string for pattern matching
                    payload_str = payload.hex()

            for pattern_info in self.malicious_patterns:
                pattern = pattern_info.get('pattern', '')
                level = pattern_info.get('level', 'MEDIUM')
                description = pattern_info.get('description', 'Suspicious pattern')
                if re.search(pattern, payload_str, re.IGNORECASE):
                    score = THREAT_LEVELS[level]['score']
                    return {
                        'type': 'malicious_pattern',
                        'score': score,
                        'message': f"{description}: {pattern}",
                        'level': level,
                        'pattern': pattern
                    }
        except Exception as e:
            logger.debug(f"Error checking payload: {e}")

        return None

    def _check_port_scan(self, packet_info: Dict) -> Optional[Dict]:
        """Detect port scanning activity with time-window analysis"""
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol')
        timestamp = packet_info.get('timestamp', 0)

        if not all([src_ip, dst_ip, dst_port, protocol in ['TCP', 'UDP']]):
            return None

        key = (src_ip, dst_ip)
        if key not in self.port_scan_tracker:
            self.port_scan_tracker[key] = {'ports': set(), 'first_seen': timestamp, 'last_seen': timestamp}

        tracker = self.port_scan_tracker[key]
        tracker['ports'].add(dst_port)
        tracker['last_seen'] = timestamp

        # Cleanup old entries (remove if not seen in baseline_window)
        current_time = timestamp
        keys_to_remove = []
        for k, v in self.port_scan_tracker.items():
            if current_time - v['last_seen'] > self.baseline_window:
                keys_to_remove.append(k)
        for k in keys_to_remove:
            del self.port_scan_tracker[k]

        # Check if this looks like a port scan
        unique_ports = len(tracker['ports'])
        if unique_ports >= self.port_scan_threshold:
            score = THREAT_LEVELS['HIGH']['score']
            return {
                'type': 'port_scan',
                'score': score,
                'message': f"Possible port scan from {src_ip} to {dst_ip} ({unique_ports} unique ports in {self.baseline_window}s window)",
                'level': 'HIGH'
            }

        # Cleanup tracker if too large to prevent memory leak
        if len(self.port_scan_tracker) > self.max_tracker_entries:
            keys_to_remove = list(self.port_scan_tracker.keys())[:self.max_tracker_entries // 2]
            for key in keys_to_remove:
                del self.port_scan_tracker[key]

        return None

    def _normalize_tcp_flags(self, flags) -> int:
        """
        Normalize TCP flags to integer value

        Args:
            flags: Can be int, FlagValue, or string representation

        Returns:
            Integer flag value
        """
        if flags is None:
            return 0
        if isinstance(flags, int):
            return flags
        if hasattr(flags, 'value'):  # Scapy FlagValue
            return int(flags.value)
        if hasattr(flags, '__int__'):
            return int(flags)
        if isinstance(flags, str):
            # Scapy can return string like "S", "SF", etc.
            flag_map = {
                'F': 0x01,  # FIN
                'S': 0x02,  # SYN
                'R': 0x04,  # RST
                'P': 0x08,  # PSH
                'A': 0x10,  # ACK
                'U': 0x20,  # URG
                'E': 0x40,  # ECE
                'C': 0x80,  # CWR
            }
            value = 0
            for char in flags:
                if char in flag_map:
                    value |= flag_map[char]
            return value
        return 0

    def _check_protocol_anomalies(self, packet_info: Dict) -> Optional[Dict]:
        """Check for protocol anomalies"""
        protocol = packet_info.get('protocol')
        info = packet_info.get('info', {})
        flags = info.get('tcp_flags')

        # Check for suspicious TCP flags (e.g., NULL scan, XMAS scan)
        if protocol == 'TCP' and flags is not None:
            flags_value = self._normalize_tcp_flags(flags)

            # NULL scan: no flags set
            if flags_value == 0:
                return {
                    'type': 'null_scan',
                    'score': THREAT_LEVELS['HIGH']['score'],
                    'message': 'NULL scan detected (stealth port scan)',
                    'level': 'HIGH'
                }

            # XMAS scan: FIN, PSH, URG flags set (0x01 | 0x08 | 0x20 = 0x29)
            if (flags_value & 0x29) == 0x29:
                return {
                    'type': 'xmas_scan',
                    'score': THREAT_LEVELS['HIGH']['score'],
                    'message': 'XMAS scan detected (stealth port scan)',
                    'level': 'HIGH'
                }

        # Check for ICMP anomalies
        if protocol == 'ICMP':
            icmp_type = packet_info.get('info', {}).get('icmp_type')
            if icmp_type == 8:  # Echo request flood could indicate DoS
                return {
                    'type': 'icmp_flood',
                    'score': THREAT_LEVELS['MEDIUM']['score'],
                    'message': 'ICMP echo request (potential DoS)',
                    'level': 'MEDIUM'
                }

        return None

    def _check_arp_spoofing(self, packet_info: Dict) -> Optional[Dict]:
        """Detect potential ARP spoofing with time-window analysis"""
        src_ip = packet_info.get('src_ip')
        src_mac = packet_info.get('src_mac')
        timestamp = packet_info.get('timestamp', 0)

        if not src_ip or not src_mac:
            return None

        # Track IP -> list of (mac, timestamp) for time-window analysis
        if src_ip not in self.arp_cache:
            self.arp_cache[src_ip] = []

        entries = self.arp_cache[src_ip]

        # Check for MAC changes within the configured time window
        current_time = timestamp

        # Clean old entries outside time window
        entries[:] = [(mac, ts) for mac, ts in entries if current_time - ts < self.arp_time_window]

        # If we have existing MACs in the window, check for conflict
        unique_macs = set(mac for mac, ts in entries)
        if unique_macs and src_mac not in unique_macs:
            # Multiple different MACs for same IP in short time = suspicious
            return {
                'type': 'arp_spoofing',
                'score': THREAT_LEVELS['CRITICAL']['score'],
                'message': f'ARP spoofing detected! IP {src_ip} changed MAC from {list(unique_macs)[0]} to {src_mac} within {self.arp_time_window}s',
                'level': 'CRITICAL'
            }

        # Add current MAC/timestamp if not already present
        if src_mac not in [mac for mac, ts in entries]:
            entries.append((src_mac, current_time))

        # Cleanup cache if too large to prevent memory leak
        if len(self.arp_cache) > self.max_tracker_entries:
            keys_to_remove = list(self.arp_cache.keys())[:self.max_tracker_entries // 2]
            for key in keys_to_remove:
                del self.arp_cache[key]

        return None

    def _check_baseline_anomaly(self, packet_info: Dict) -> Optional[Dict]:
        """Detect anomalies based on deviation from established baseline"""
        timestamp = packet_info.get('timestamp', 0)
        src_ip = packet_info.get('src_ip')
        protocol = packet_info.get('protocol')
        dst_port = packet_info.get('dst_port')

        if not src_ip or not protocol:
            return None

        # Track packet rate
        self.packet_rate_history.append((timestamp, 1))
        # Keep only recent history
        cutoff = timestamp - self.baseline_window
        self.packet_rate_history = [(ts, cnt) for ts, cnt in self.packet_rate_history if ts > cutoff]

        # Calculate current packet rate (packets per second in baseline window)
        if len(self.packet_rate_history) > 10:  # Need some data
            rate = len(self.packet_rate_history) / self.baseline_window
            # Sudden spike detection
            if rate > self.baseline_rate_threshold:
                # Rate-limiting: only alert once per cooldown period for high_rate
                cooldown_key = (src_ip, 'high_packet_rate')
                last_alert = self.baseline_alert_cooldown.get(cooldown_key, 0)
                if timestamp - last_alert > self.baseline_cooldown_period:
                    self.baseline_alert_cooldown[cooldown_key] = timestamp
                    return {
                        'type': 'high_packet_rate',
                        'score': THREAT_LEVELS['MEDIUM']['score'],
                        'message': f'High packet rate detected: {rate:.1f} pps (threshold: {self.baseline_rate_threshold} pps)',
                        'level': 'MEDIUM'
                    }

        # Track port distribution per source IP (with time-window cleanup)
        if dst_port and protocol in ['TCP', 'UDP']:
            if src_ip not in self.port_distribution:
                self.port_distribution[src_ip] = {'ports': set(), 'first_seen': timestamp, 'last_seen': timestamp}
            else:
                self.port_distribution[src_ip]['last_seen'] = timestamp

            self.port_distribution[src_ip]['ports'].add(dst_port)

            # Cleanup old entries (remove IPs not seen in baseline_window)
            current_time = timestamp
            keys_to_remove = []
            for ip, data in self.port_distribution.items():
                if current_time - data['last_seen'] > self.baseline_window:
                    keys_to_remove.append(ip)
            for key in keys_to_remove:
                del self.port_distribution[key]

            # Check for excessive port diversity from single source
            port_count = len(self.port_distribution[src_ip]['ports'])
            if port_count > self.baseline_port_diversity_threshold:
                # Rate-limiting: only alert once per cooldown period per source
                cooldown_key = (src_ip, 'excessive_port_diversity')
                last_alert = self.baseline_alert_cooldown.get(cooldown_key, 0)
                if timestamp - last_alert > self.baseline_cooldown_period:
                    self.baseline_alert_cooldown[cooldown_key] = timestamp
                    return {
                        'type': 'excessive_port_diversity',
                        'score': THREAT_LEVELS['HIGH']['score'],
                        'message': f'Source {src_ip} contacting {port_count} unique ports (threshold: {self.baseline_port_diversity_threshold})',
                        'level': 'HIGH'
                    }

        # Track protocol distribution (for future analysis, no alerts)
        if protocol:
            self.protocol_distribution[protocol] = self.protocol_distribution.get(protocol, 0) + 1

        return None

    def _create_summary(self, packet_info: Dict) -> str:
        """Create a human-readable packet summary"""
        src_ip = packet_info.get('src_ip', '??')
        dst_ip = packet_info.get('dst_ip', '??')
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        protocol = packet_info.get('protocol', '??')

        if src_port and dst_port:
            return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} [{protocol}]"
        else:
            return f"{src_ip} -> {dst_ip} [{protocol}]"

    def get_statistics(self) -> Dict:
        """Get threat statistics"""
        stats = {
            'total_packets': self.total_packets_analyzed,
            'total_threats': len(self.threat_history),
            'by_level': {},
            'by_type': {}
        }

        for level in THREAT_LEVELS:
            stats['by_level'][level] = sum(
                1 for t in self.threat_history
                if t['threat_level'] == level
            )

        for threat in self.threat_history:
            for t in threat['threats']:
                t_type = t['type']
                stats['by_type'][t_type] = stats['by_type'].get(t_type, 0) + 1

        return stats

    def reset(self) -> None:
        """Reset analyzer state"""
        self.threat_history.clear()
        self.port_scan_tracker.clear()
        self.arp_cache.clear()
        self.packet_rate_history.clear()
        self.port_distribution.clear()
        self.protocol_distribution.clear()
        self.baseline_alert_cooldown.clear()
        self.total_packets_analyzed = 0
