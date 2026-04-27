"""
Command Line Interface - Main entry point for DONET
"""

import argparse
import logging
import sys
import time
from typing import Optional
from datetime import datetime

from packet_capture import PacketCapture
from threat_analyzer import ThreatAnalyzer
from reporter import Reporter
from config import Config

logger = logging.getLogger(__name__)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='DONET - Real-time packet threat detection with emoji indicators',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i eth0                          # Capture on eth0 interface
  %(prog)s -i eth0 -f "tcp port 80"         # Filter HTTP traffic
  %(prog)s -i eth0 -c 100                   # Capture 100 packets
  %(prog)s -i eth0 --live                   # Live monitoring mode
  %(prog)s -i eth0 --show-safe              # Show all packets including safe ones
  %(prog)s --list-interfaces                # List available interfaces
        """
    )

    # Interface options
    parser.add_argument(
        '-i', '--interface',
        type=str,
        help='Network interface to capture (default: auto)'
    )

    # Filter options
    parser.add_argument(
        '-f', '--filter',
        type=str,
        default=None,
        help='BPF filter expression (e.g., "tcp port 80", "icmp")'
    )

    # Capture options
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=0,
        help='Number of packets to capture (default: unlimited)'
    )

    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=None,
        help='Capture timeout in seconds (default: none)'
    )

    # Output options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with packet details'
    )

    parser.add_argument(
        '--show-safe',
        action='store_true',
        help='Show packets with no threats (SAFE level)'
    )

    parser.add_argument(
        '--live',
        action='store_true',
        help='Live monitoring mode with compact output'
    )

    # Configuration options
    parser.add_argument(
        '--config',
        type=str,
        default=None,
        help='Path to configuration file (YAML)'
    )

    # Utility options
    parser.add_argument(
        '--list-interfaces',
        action='store_true',
        help='List available network interfaces and exit'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    # Report output options
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Save report to file (supports .txt, .json, .html formats)'
    )

    return parser.parse_args()


def list_interfaces():
    """List available network interfaces"""
    print("\nAvailable Network Interfaces:")
    print("-" * 40)
    try:
        interfaces = PacketCapture.get_interfaces()
        for iface in interfaces:
            print(f"  • {iface}")
    except Exception as e:
        print(f"Error listing interfaces: {e}")
        sys.exit(1)


def packet_callback(packet, analyzer, reporter, config, live_mode=False):
    """
    Callback function for each captured packet

    Args:
        packet: Scapy packet object
        analyzer: ThreatAnalyzer instance
        reporter: Reporter instance
        config: Configuration object
        live_mode: Whether to use live compact output
    """
    try:
        # Parse packet (optionally include raw packet for debugging)
        include_raw = config.get('reporting', 'include_raw', default=False)
        packet_info = PacketCapture.parse_packet(packet, include_raw=include_raw)

        # Analyze for threats
        threat_result = analyzer.analyze_packet(packet_info)

        # Display result
        if live_mode:
            reporter.print_live_packet(threat_result, packet_info)
        else:
            reporter.print_packet_threat(threat_result, packet_info)

    except Exception as e:
        logger.error(f"Error processing packet: {e}")


def main():
    """Main entry point"""
    args = parse_arguments()

    # Handle utility commands
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)

    # Initialize configuration
    config = Config(config_path=args.config)

    # Validate configuration
    config_errors = config.validate()
    if config_errors:
        for error in config_errors:
            logger.warning(f"Configuration validation: {error}")

    # Configure logging from config
    log_config = config.get('logging', default={})
    log_level = log_config.get('level', 'INFO')
    log_file = log_config.get('file', None)

    # Set up logging handlers
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=log_config.get('max_bytes', 10485760),
            backupCount=log_config.get('backup_count', 5)
        )
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        handlers.append(file_handler)

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

    # Initialize components
    reporter = Reporter(verbose=args.verbose, show_safe=args.show_safe)
    analyzer = ThreatAnalyzer(config=config)

    # Print banner
    reporter.print_banner()
    reporter.print_interface_info(args.interface, args.filter)

    # Validate interface if specified
    if args.interface:
        available = PacketCapture.get_interfaces()
        if args.interface not in available:
            reporter.print_error(f"Interface '{args.interface}' not found.")
            reporter.print_info(f"Available interfaces: {', '.join(available)}")
            sys.exit(1)

    # Create packet capture
    sample_rate = config.get('performance', 'packet_sampling', default=1)
    capture = PacketCapture(interface=args.interface, filter_expr=args.filter, sample_rate=sample_rate)

    # Prepare callback wrapper
    def make_callback(pkt):
        packet_callback(pkt, analyzer, reporter, config, live_mode=args.live)

    start_time = time.time()

    try:
        if args.live:
            # Live mode: continuous display
            print("\nStarting live capture (Ctrl+C to stop)...")
            print("-" * 100)

        # Start capture
        capture.start_callback(
            count=args.count,
            timeout=args.timeout,
            callback=make_callback
        )

    except KeyboardInterrupt:
        print("\n\nCapture interrupted by user.")
    except PermissionError:
        reporter.print_error("Permission denied. Run with sudo/administrator privileges.")
        sys.exit(1)
    except Exception as e:
        reporter.print_error(f"Failed to start capture: {e}")
        logger.exception("Capture failed")
        sys.exit(1)
    finally:
        # Calculate duration
        duration = time.time() - start_time

        # Get statistics
        stats = analyzer.get_statistics()
        stats['duration'] = duration
        stats['packets_captured'] = getattr(capture, 'packets_count', 0)  # Total packets seen by capture
        stats['packets_analyzed'] = stats['total_packets']  # Packets that went through analysis (sampled)
        if sample_rate > 1:
            stats['sampling_rate'] = sample_rate
            # Adjust effective packets per second to reflect actual traffic
            stats['effective_pps'] = stats['packets_captured'] / duration if duration > 0 else 0

        # Print statistics
        if not args.live or args.count > 0:
            reporter.print_statistics(stats, duration)

        # Save report to file if requested
        if args.output:
            reporter.save_report(args.output, stats, duration, analyzer.threat_history)

        # Exit with appropriate code
        if stats.get('total_threats', 0) > 0:
            sys.exit(1)  # Threats detected
        else:
            sys.exit(0)  # Clean capture


if __name__ == '__main__':
    main()
