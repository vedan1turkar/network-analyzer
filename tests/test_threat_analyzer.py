"""
Unit tests for ThreatAnalyzer module
"""

import pytest
import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from donet.threat_analyzer import ThreatAnalyzer, THREAT_LEVELS
from donet.config import Config


class TestThreatAnalyzer:
    """Test suite for ThreatAnalyzer"""

    def setup_method(self):
        """Set up test fixtures"""
        self.config = Config()
        self.analyzer = ThreatAnalyzer(config=self.config)

    def teardown_method(self):
        """Clean up after tests"""
        self.analyzer.reset()

    def test_initialization(self):
        """Test analyzer initialization"""
        assert self.analyzer.threat_history == []
        assert self.analyzer.total_packets_analyzed == 0
        assert self.analyzer.port_scan_tracker == {}
        assert self.analyzer.arp_cache == {}

    def test_suspicious_port_detection(self):
        """Test detection of suspicious ports"""
        # Test SSH port (22)
        packet_info = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 22,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': None
        }
        result = self.analyzer.analyze_packet(packet_info)
        assert result['threat_level'] in ['MEDIUM', 'HIGH']  # Depends on config
        assert any(t['type'] == 'suspicious_port' for t in result['threats'])

    def test_malicious_pattern_detection(self):
        """Test detection of malicious payload patterns"""
        # Test SQL injection pattern
        packet_info = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': b"SELECT * FROM users WHERE id='1' OR '1'='1'"
        }
        result = self.analyzer.analyze_packet(packet_info)
        assert result['threat_level'] in ['MEDIUM', 'HIGH']
        assert any(t['type'] == 'malicious_pattern' for t in result['threats'])

    def test_xss_pattern_detection(self):
        """Test XSS pattern detection"""
        packet_info = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': b"<script>alert('xss')</script>"
        }
        result = self.analyzer.analyze_packet(packet_info)
        assert result['threat_level'] in ['HIGH', 'MEDIUM']
        assert any(t['type'] == 'malicious_pattern' for t in result['threats'])

    def test_port_scan_detection(self):
        """Test port scan detection"""
        src_ip = '10.0.0.1'
        dst_ip = '10.0.0.100'
        threshold = self.analyzer.port_scan_threshold

        # Send packets to multiple ports from same source
        for port in range(1, threshold + 1):
            packet_info = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': 54321,
                'dst_port': port,
                'protocol': 'TCP',
                'timestamp': 1234567890.0 + port,
                'payload': None
            }
            self.analyzer.analyze_packet(packet_info)

        # The last packet should trigger port scan detection
        result = self.analyzer.analyze_packet(packet_info)
        assert any(t['type'] == 'port_scan' for t in result['threats'])

    def test_arp_spoofing_detection(self):
        """Test ARP spoofing detection with time window"""
        ip = '192.168.1.100'
        mac1 = '00:11:22:33:44:55'
        mac2 = 'aa:bb:cc:dd:ee:ff'

        # First ARP packet with MAC1
        packet1 = {
            'src_ip': ip,
            'src_mac': mac1,
            'dst_ip': '192.168.1.1',
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'protocol': 'ARP',
            'timestamp': 1234567890.0,
            'payload': None
        }
        self.analyzer.analyze_packet(packet1)
        # No threat yet
        assert len(self.analyzer.threat_history) == 0

        # Second ARP packet with different MAC2 within time window
        packet2 = {
            'src_ip': ip,
            'src_mac': mac2,
            'dst_ip': '192.168.1.1',
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'protocol': 'ARP',
            'timestamp': 1234567890.0 + 30,  # 30 seconds later
            'payload': None
        }
        result = self.analyzer.analyze_packet(packet2)
        # Should detect ARP spoofing
        assert result['threat_level'] == 'CRITICAL'
        assert any(t['type'] == 'arp_spoofing' for t in result['threats'])

    def test_arp_spoofing_time_window_expiry(self):
        """Test that ARP spoofing detection respects time window"""
        ip = '192.168.1.100'
        mac1 = '00:11:22:33:44:55'
        mac2 = 'aa:bb:cc:dd:ee:ff'
        time_window = self.analyzer.arp_time_window

        # First ARP
        packet1 = {
            'src_ip': ip,
            'src_mac': mac1,
            'dst_ip': '192.168.1.1',
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'protocol': 'ARP',
            'timestamp': 1234567890.0,
            'payload': None
        }
        self.analyzer.analyze_packet(packet1)

        # Second ARP with different MAC after time window expires
        packet2 = {
            'src_ip': ip,
            'src_mac': mac2,
            'dst_ip': '192.168.1.1',
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'protocol': 'ARP',
            'timestamp': 1234567890.0 + time_window + 10,  # Outside window
            'payload': None
        }
        result = self.analyzer.analyze_packet(packet2)
        # Should NOT detect ARP spoofing (old entry expired)
        assert result['threat_level'] != 'CRITICAL' or not any(t['type'] == 'arp_spoofing' for t in result['threats'])

    def test_packet_counting(self):
        """Test that packet counter increments correctly"""
        packet_info = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': None
        }
        initial_count = self.analyzer.total_packets_analyzed

        for _ in range(5):
            self.analyzer.analyze_packet(packet_info)

        assert self.analyzer.total_packets_analyzed == initial_count + 5

    def test_statistics(self):
        """Test statistics generation"""
        # Analyze some packets
        packet_safe = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': None
        }
        packet_threat = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 22,  # Suspicious port
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': None
        }

        self.analyzer.analyze_packet(packet_safe)
        self.analyzer.analyze_packet(packet_threat)

        stats = self.analyzer.get_statistics()
        assert stats['total_packets'] == 2
        assert stats['total_threats'] >= 1
        assert 'by_level' in stats
        assert 'by_type' in stats

    def test_reset(self):
        """Test analyzer reset"""
        # Add some data
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 22,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': None
        }
        self.analyzer.analyze_packet(packet)
        self.analyzer.reset()

        assert self.analyzer.threat_history == []
        assert self.analyzer.total_packets_analyzed == 0
        assert self.analyzer.port_scan_tracker == {}
        assert self.analyzer.arp_cache == {}

    def test_null_scan_detection(self):
        """Test NULL scan detection"""
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': None,
            'info': {'tcp_flags': 0}  # No flags set
        }
        result = self.analyzer.analyze_packet(packet)
        assert any(t['type'] == 'null_scan' for t in result['threats'])

    def test_xmas_scan_detection(self):
        """Test XMAS scan detection"""
        # TCP flags: FIN=0x01, PSH=0x08, URG=0x20 = 0x29
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.50',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 'TCP',
            'timestamp': 1234567890.0,
            'payload': None,
            'info': {'tcp_flags': 0x29}  # FIN+PSH+URG
        }
        result = self.analyzer.analyze_packet(packet)
        assert any(t['type'] == 'xmas_scan' for t in result['threats'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
