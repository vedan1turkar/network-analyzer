"""
Reporter Module - Formats threat reports with emojis and colors for DONET
"""

import logging
from typing import Dict, List
from datetime import datetime

import json
import os

try:
    import colorama
    colorama.init()
    COLORS_ENABLED = True
except ImportError:
    COLORS_ENABLED = False

logger = logging.getLogger(__name__)

# Emoji mappings for threat levels
THREAT_EMOJIS = {
    'CRITICAL': '🚨',
    'HIGH': '⚠️',
    'MEDIUM': '⚡',
    'LOW': 'ℹ️',
    'SAFE': '✅'
}

# Color codes (using colorama or ANSI)
COLOR_CODES = {
    'CRITICAL': '\033[91m',   # Bright Red
    'HIGH': '\033[93m',       # Bright Yellow
    'MEDIUM': '\033[94m',     # Bright Blue
    'LOW': '\033[96m',        # Bright Cyan
    'SAFE': '\033[92m',       # Bright Green
    'RESET': '\033[0m',
    'BOLD': '\033[1m'
}

# Protocol icons
PROTOCOL_ICONS = {
    'TCP': '🔗',
    'UDP': '📡',
    'ICMP': '📢',
    'HTTP': '🌐',
    'HTTPS': '🔒',
    'DNS': '🔍',
    'SSH': '🔐',
    'FTP': '📁',
    'SMTP': '📧',
    'ARP': '🔁'
}


class Reporter:
    """Formats and displays threat reports"""

    def __init__(self, verbose: bool = False, show_safe: bool = False):
        """
        Initialize reporter

        Args:
            verbose: Show detailed packet information
            show_safe: Show packets with no threats
        """
        self.verbose = verbose
        self.show_safe = show_safe
        self.report_count = 0
        self.start_time = datetime.now()

    def colorize(self, text: str, level: str) -> str:
        """Apply color to text based on threat level"""
        if not COLORS_ENABLED:
            return text

        color = COLOR_CODES.get(level, '')
        reset = COLOR_CODES['RESET']
        return f"{color}{text}{reset}"

    def get_emoji(self, level: str) -> str:
        """Get emoji for threat level"""
        return THREAT_EMOJIS.get(level, '❓')

    def get_protocol_icon(self, protocol: str) -> str:
        """Get icon for protocol"""
        return PROTOCOL_ICONS.get(protocol.upper(), '📦')

    def print_banner(self) -> None:
        """Print tool banner"""
        banner = f"""
{self.colorize('='*60, 'CRITICAL')}
{self.colorize('  DONET - Packet Threat Detection', 'BOLD')}
{self.colorize('  Version 1.0.0', 'SAFE')}
{self.colorize('='*60, 'CRITICAL')}
        """
        print(banner)

    def print_packet_threat(self, threat_result: Dict, packet_info: Dict) -> None:
        """
        Print threat report for a single packet

        Args:
            threat_result: Threat analysis result
            packet_info: Original packet information
        """
        level = threat_result['threat_level']
        emoji = self.get_emoji(level)

        if level == 'SAFE' and not self.show_safe:
            return

        self.report_count += 1

        # Header line with threat level
        print(f"\n{emoji} {self.colorize(f'[{level}]', level)} "
              f"{threat_result['description']}")

        # Packet summary
        print(f"   📦 Packet: {threat_result['packet_summary']}")

        # Detailed threat information
        if threat_result['threats']:
            print(f"   🎯 Threat Score: {threat_result['threat_score']}/100")
            for i, threat in enumerate(threat_result['threats'], 1):
                print(f"   • {threat['message']}")

        # Verbose output
        if self.verbose:
            self._print_verbose_details(packet_info, level)

    def _print_verbose_details(self, packet_info: Dict, level: str) -> None:
        """Print verbose packet details"""
        print(f"   {'-'*50}")
        print(f"   📊 Details:")
        print(f"      Length: {packet_info.get('length', 0)} bytes")
        print(f"      Timestamp: {datetime.fromtimestamp(packet_info.get('timestamp', 0))}")
        print(f"      Layers: {', '.join(packet_info.get('layers', []))}")

        if packet_info.get('src_mac') and packet_info.get('dst_mac'):
            print(f"      MAC: {packet_info['src_mac']} → {packet_info['dst_mac']}")

        if packet_info.get('payload'):
            payload_preview = str(packet_info['payload'])[:50]
            print(f"      Payload: {payload_preview}...")

    def print_statistics(self, stats: Dict, duration: float) -> None:
        """Print summary statistics"""
        print(f"\n{self.colorize('='*60, 'CRITICAL')}")
        print(f"{self.colorize('  CAPTURE STATISTICS', 'BOLD')}")
        print(f"{self.colorize('='*60, 'CRITICAL')}")

        print(f"\n⏱️  Duration: {duration:.2f} seconds")
        print(f"📊 Total packets analyzed: {stats.get('total_packets', 0)}")
        print(f"🚨 Threats detected: {stats.get('total_threats', 0)}")

        # Threat level breakdown
        print(f"\n{self.colorize('  Threat Level Breakdown:', 'BOLD')}")
        for level, count in stats.get('by_level', {}).items():
            if count > 0:
                emoji = self.get_emoji(level)
                print(f"   {emoji} {level}: {count}")

        # Threat type breakdown
        if stats.get('by_type'):
            print(f"\n{self.colorize('  Threat Types:', 'BOLD')}")
            for t_type, count in stats['by_type'].items():
                print(f"   • {t_type.replace('_', ' ').title()}: {count}")

        print(f"\n{self.colorize('='*60, 'CRITICAL')}")

    def print_interface_info(self, interface: str, filter_expr: str) -> None:
        """Print capture configuration"""
        print(f"\n{self.colorize('  Configuration:', 'BOLD')}")
        print(f"   🌐 Interface: {interface or 'default'}")
        print(f"   🔍 Filter: {filter_expr or 'none'}")
        print(f"   ⚙️  Verbose: {self.verbose}")
        print(f"   📢 Show safe: {self.show_safe}")

    def print_error(self, message: str) -> None:
        """Print error message"""
        print(f"{self.colorize('❌ ERROR:', 'CRITICAL')} {message}")

    def print_warning(self, message: str) -> None:
        """Print warning message"""
        print(f"{self.colorize('⚠️  WARNING:', 'HIGH')} {message}")

    def print_info(self, message: str) -> None:
        """Print info message"""
        print(f"{self.colorize('ℹ️  INFO:', 'SAFE')} {message}")

    def print_live_header(self) -> None:
        """Print header for live monitoring mode"""
        print(f"\n{self.colorize('~~~~~~~~~~~~~~~', 'BOLD')}")
        print(f"{self.colorize('  LIVE PACKET MONITORING', 'BOLD')}")
        print(f"{self.colorize('~~~~~~~~~~~~~~~', 'BOLD')}")
        print(f"\n{'Time':<8} {'Level':<10} {'Source':<20} {'Destination':<20} {'Protocol':<8} {'Info'}")
        print(f"{'-'*100}")

    def print_live_packet(self, threat_result: Dict, packet_info: Dict) -> None:
        """Print compact live packet info"""
        level = threat_result['threat_level']
        emoji = self.get_emoji(level)

        timestamp = datetime.fromtimestamp(packet_info.get('timestamp', 0)).strftime('%H:%M:%S')
        src = f"{packet_info.get('src_ip', '?')}:{packet_info.get('src_port', '?')}"
        dst = f"{packet_info.get('dst_ip', '?')}:{packet_info.get('dst_port', '?')}"
        protocol = packet_info.get('protocol', '?')
        protocol_icon = self.get_protocol_icon(protocol)

        # Colorize level
        level_colored = self.colorize(f"{level:<10}", level)

        print(f"{timestamp:<8} {emoji} {level_colored} {src:<20} {dst:<20} {protocol_icon} {protocol:<8} {threat_result['packet_summary']}")

    def save_report(self, filepath: str, stats: Dict, duration: float, threats: List[Dict] = None) -> bool:
        """
        Save report to file

        Args:
            filepath: Output file path
            stats: Statistics dictionary
            duration: Capture duration in seconds
            threats: Optional list of threat details

        Returns:
            True if successful, False otherwise
        """
        ext = os.path.splitext(filepath)[1].lower()

        try:
            if ext == '.json':
                return self._save_json(filepath, stats, duration)
            elif ext == '.html':
                return self._save_html(filepath, stats, duration, threats)
            else:
                return self._save_text(filepath, stats, duration)
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False

    def _save_text(self, filepath: str, stats: Dict, duration: float) -> bool:
        """Save report as plain text"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("  DONET - Report\n")
            f.write("  Version 1.0.0\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"Duration: {duration:.2f} seconds\n")
            f.write(f"Total Packets: {stats.get('total_packets', 0)}\n")
            f.write(f"Threats Detected: {stats.get('total_threats', 0)}\n\n")

            f.write("Threat Level Breakdown:\n")
            for level, count in stats.get('by_level', {}).items():
                if count > 0:
                    f.write(f"  - {level}: {count}\n")

            if stats.get('by_type'):
                f.write("\nThreat Types:\n")
                for t_type, count in stats['by_type'].items():
                    f.write(f"  - {t_type.replace('_', ' ').title()}: {count}\n")

        print(f"✅ Report saved to {filepath}")
        return True

    def _save_json(self, filepath: str, stats: Dict, duration: float) -> bool:
        """Save report as JSON"""
        report = {
            'version': '1.0.0',
            'duration_seconds': duration,
            'total_packets': stats.get('total_packets', 0),
            'total_threats': stats.get('total_threats', 0),
            'threat_levels': stats.get('by_level', {}),
            'threat_types': stats.get('by_type', {}),
            'timestamp': datetime.now().isoformat()
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        print(f"✅ JSON report saved to {filepath}")
        return True

    def _save_html(self, filepath: str, stats: Dict, duration: float, threats: List[Dict] = None) -> bool:
        """Save report as HTML"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>DONET Report</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background: #1e1e1e; color: #ccc; }}
        h1 {{ color: #4fc1ff; }}
        .summary {{ background: #2d2d2d; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .threat-critical {{ color: #ff6b6b; }}
        .threat-high {{ color: #ffd93d; }}
        .threat-medium {{ color: #6bcfff; }}
        .threat-low {{ color: #74c0fc; }}
        .threat-safe {{ color: #69db7c; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #3e3e3e; }}
        th {{ background: #252526; }}
    </style>
</head>
<body>
    <h1>🛡️ DONET Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Duration:</strong> {duration:.2f} seconds</p>
        <p><strong>Total Packets:</strong> {stats.get('total_packets', 0)}</p>
        <p><strong>Threats Detected:</strong> {stats.get('total_threats', 0)}</p>
    </div>
    
    <h2>Threat Level Breakdown</h2>
    <table>
        <tr><th>Level</th><th>Count</th></tr>
"""

        for level, count in stats.get('by_level', {}).items():
            if count > 0:
                html += f"        <tr><td class='threat-{level.lower()}'>{level}</td><td>{count}</td></tr>\n"

        html += """    </table>
    
    <h2>Threat Types</h2>
    <table>
        <tr><th>Type</th><th>Count</th></tr>
"""

        if stats.get('by_type'):
            for t_type, count in stats['by_type'].items():
                html += f"        <tr><td>{t_type.replace('_', ' ').title()}</td><td>{count}</td></tr>\n"

        html += """    </table>
    
    <h2>Detected Threats</h2>
    <table>
        <tr><th>Time</th><th>Level</th><th>Type</th><th>Message</th><th>Packet Summary</th></tr>
"""

        if threats:
            for threat in threats:
                ts = datetime.fromtimestamp(threat.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')
                level = threat['threat_level']
                threat_type = threat['threats'][0]['type'] if threat.get('threats') else 'unknown'
                message = threat['threats'][0]['message'] if threat.get('threats') else threat.get('description', '')
                summary = threat.get('packet_summary', '')
                html += f"        <tr><td>{ts}</td><td class='threat-{level.lower()}'>{level}</td><td>{threat_type}</td><td>{message}</td><td>{summary}</td></tr>\n"
        else:
            html += "        <tr><td colspan='5'>No threats detected</td></tr>\n"

        html += """    </table>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"✅ HTML report saved to {filepath}")
        return True
