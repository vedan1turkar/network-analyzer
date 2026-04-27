"""
Packet Capture Module - Captures network packets using scapy
"""

import logging
from typing import Optional, Callable
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, DNS, Raw
from scapy.error import Scapy_Exception

logger = logging.getLogger(__name__)


class PacketCapture:
    """Handles network packet capture"""

    def __init__(self, interface: Optional[str] = None, filter_expr: Optional[str] = None, sample_rate: int = 1):
        """
        Initialize packet capture

        Args:
            interface: Network interface to capture from (None for default)
            filter_expr: BPF filter expression (e.g., "tcp port 80")
            sample_rate: Process every Nth packet (1 = all packets)
        """
        self.interface = interface
        self.filter_expr = filter_expr
        self.packets = []
        self._stop_capture = False
        self.sample_rate = max(1, sample_rate)
        self._packet_counter = 0

    def _packet_handler(self, packet) -> None:
        """Internal handler for captured packets"""
        if not self._stop_capture:
            self.packets.append(packet)

    def start_capture(self, count: int = 0, timeout: Optional[int] = None,
                      callback: Optional[Callable] = None) -> list:
        """
        Start capturing packets

        Args:
            count: Number of packets to capture (0 for unlimited)
            timeout: Capture timeout in seconds
            callback: Optional callback function for each packet

        Returns:
            List of captured packets
        """
        logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
        logger.info(f"Filter: {self.filter_expr or 'none'}")

        try:
            if callback:
                # Use callback mode for real-time processing
                sniff(iface=self.interface,
                      filter=self.filter_expr,
                      prn=callback,
                      count=count,
                      timeout=timeout,
                      store=False)
            else:
                # Store packets internally
                sniff(iface=self.interface,
                      filter=self.filter_expr,
                      prn=self._packet_handler,
                      count=count,
                      timeout=timeout)
                return self.packets
        except Scapy_Exception as e:
            logger.error(f"Scapy error during capture: {e}")
            raise
        except PermissionError:
            logger.error("Permission denied. Run with sudo/administrator privileges.")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during capture: {e}")
            raise

    def stop(self) -> None:
        """Stop ongoing capture"""
        self._stop_capture = True

    def start_callback(self, count: int = 0, timeout: Optional[int] = None,
                     callback: Optional[Callable] = None) -> int:
        """
        Start capture with callback for real-time processing

        Args:
            count: Number of packets to capture (0 for unlimited)
            timeout: Capture timeout in seconds
            callback: Callback function for each packet

        Returns:
            Number of packets captured (total, not sampled)
        """
        self.packets_count = 0

        def counting_callback(pkt):
            self.packets_count += 1
            # Apply sampling: only process every Nth packet
            if self.sample_rate == 1 or self.packets_count % self.sample_rate == 0:
                callback(pkt)

        sniff(iface=self.interface,
              filter=self.filter_expr,
              prn=counting_callback,
              count=count,
              timeout=timeout,
              store=False)
        return self.packets_count

    @staticmethod
    def get_interfaces() -> list:
        """Get list of available network interfaces"""
        from scapy.all import get_if_list
        return get_if_list()

    @staticmethod
    def parse_packet(packet, include_raw: bool = False) -> dict:
        """
        Parse a packet into a structured dictionary

        Args:
            packet: Scapy packet object
            include_raw: Whether to include raw packet object (memory intensive)

        Returns:
            Dictionary with parsed packet information
        """
        result = {
            'timestamp': packet.time,
            'layers': [],
            'src_ip': None,
            'dst_ip': None,
            'src_mac': None,
            'dst_mac': None,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'length': len(packet),
            'payload': None,
            'info': {}
        }
        if include_raw:
            result['raw'] = packet

        # Extract Ethernet layer
        if packet.haslayer(Ether):
            result['src_mac'] = packet[Ether].src
            result['dst_mac'] = packet[Ether].dst
            result['layers'].append('Ether')

        # Extract IP layer (IPv4)
        if packet.haslayer(IP):
            result['src_ip'] = packet[IP].src
            result['dst_ip'] = packet[IP].dst
            result['layers'].append('IP')
            result['info']['ip_ttl'] = packet[IP].ttl
            result['info']['ip_flags'] = packet[IP].flags

        # Extract IPv6 layer
        if packet.haslayer(IPv6):
            result['src_ip'] = packet[IPv6].src
            result['dst_ip'] = packet[IPv6].dst
            result['layers'].append('IPv6')
            result['info']['ip_ttl'] = packet[IPv6].hlim
            # IPv6 flow info if available
            if hasattr(packet[IPv6], 'fl'):
                result['info']['ip_flow'] = packet[IPv6].fl
            # Set default protocol to IPv6 (overwritten by upper layers)
            result['protocol'] = 'IPv6'

        # Extract TCP layer
        if packet.haslayer(TCP):
            result['protocol'] = 'TCP'
            result['src_port'] = packet[TCP].sport
            result['dst_port'] = packet[TCP].dport
            result['layers'].append('TCP')
            result['info']['tcp_flags'] = packet[TCP].flags
            result['info']['tcp_seq'] = packet[TCP].seq
            result['info']['tcp_ack'] = packet[TCP].ack

        # Extract UDP layer
        if packet.haslayer(UDP):
            result['protocol'] = 'UDP'
            result['src_port'] = packet[UDP].sport
            result['dst_port'] = packet[UDP].dport
            result['layers'].append('UDP')

        # Extract ICMP layer (IPv4)
        if packet.haslayer(ICMP):
            result['protocol'] = 'ICMP'
            result['layers'].append('ICMP')
            result['info']['icmp_type'] = packet[ICMP].type
            result['info']['icmp_code'] = packet[ICMP].code

        # Extract ICMPv6 layer (IPv6)
        if packet.haslayer(ICMPv6):
            result['protocol'] = 'ICMPv6'
            result['layers'].append('ICMPv6')
            result['info']['icmp_type'] = packet[ICMPv6].type
            result['info']['icmp_code'] = packet[ICMPv6].code

        # Extract ARP layer
        if packet.haslayer(ARP):
            result['protocol'] = 'ARP'
            result['src_ip'] = packet[ARP].psrc
            result['dst_ip'] = packet[ARP].pdst
            result['src_mac'] = packet[ARP].hwsrc
            result['dst_mac'] = packet[ARP].hwdst
            result['layers'].append('ARP')

        # Extract DNS layer
        if packet.haslayer(DNS):
            result['protocol'] = 'DNS'
            result['layers'].append('DNS')
            result['info']['dns_qd'] = packet[DNS].qd
            result['info']['dns_an'] = packet[DNS].an

        # Extract payload
        if packet.haslayer(Raw):
            result['payload'] = packet[Raw].load
            result['layers'].append('Raw')

        return result
