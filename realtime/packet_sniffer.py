"""
RT-IDPS Packet Sniffer Module
Captures live network traffic using Scapy
"""

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("Scapy not available. Packet sniffer will run in simulation mode.")
    logger.info("To install scapy: pip install scapy")
    SCAPY_AVAILABLE = False
import sys
import os
from datetime import datetime
from collections import defaultdict

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import DETECTION_CONFIG
from utils.logger import setup_logger

# Setup logger
logger = setup_logger('PacketSniffer', log_file='logs/packet_sniffer.log')


class PacketSniffer:
    """
    Live network packet capture using Scapy
    Captures TCP, UDP, and ICMP packets for analysis
    """

    def __init__(self, interface=None):
        """
        Initialize packet sniffer

        Args:
            interface: Network interface to sniff on (None = all interfaces)
        """
        self.interface = interface or DETECTION_CONFIG['packet_capture_interface']
        self.packet_count = 0
        self.captured_packets = []
        self.running = False

        # Statistics
        self.stats = defaultdict(int)

        logger.info(f"Initialized packet sniffer on interface: {self.interface}")

    def packet_callback(self, packet):
        """
        Callback function for each captured packet

        Args:
            packet: Scapy packet object
        """
        try:
            # Check if packet has IP layer
            if not packet.haslayer(IP):
                return

            # Extract basic packet info
            packet_info = self._extract_packet_info(packet)

            if packet_info:
                self.captured_packets.append(packet_info)
                self.packet_count += 1

                # Update statistics
                self.stats['total'] += 1
                self.stats[packet_info['protocol']] += 1

                # Log periodically
                if self.packet_count % 100 == 0:
                    logger.info(f"Captured {self.packet_count} packets | "
                              f"TCP: {self.stats['TCP']} | "
                              f"UDP: {self.stats['UDP']} | "
                              f"ICMP: {self.stats['ICMP']}")

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _extract_packet_info(self, packet):
        """
        Extract relevant information from packet

        Args:
            packet: Scapy packet object

        Returns:
            Dictionary with packet information
        """
        info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'packet_size': len(packet),
            'ttl': packet[IP].ttl,
            'flags': None,
            'raw_packet': packet
        }

        # TCP packet
        if packet.haslayer(TCP):
            info['protocol'] = 'TCP'
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['flags'] = str(packet[TCP].flags)

        # UDP packet
        elif packet.haslayer(UDP):
            info['protocol'] = 'UDP'
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport

        # ICMP packet
        elif packet.haslayer(ICMP):
            info['protocol'] = 'ICMP'
            info['icmp_type'] = packet[ICMP].type
            info['icmp_code'] = packet[ICMP].code

        else:
            # Unknown protocol, skip
            return None

        return info

    def start_capture(self, count=100, timeout=None):
        """
        Start capturing packets

        Args:
            count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds (None = no timeout)

        Returns:
            List of captured packet info
        """
        logger.info("="*70)
        logger.info("STARTING PACKET CAPTURE")
        logger.info("="*70)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Count: {count if count > 0 else 'Infinite'}")
        logger.info(f"Timeout: {timeout if timeout else 'None'}")
        logger.info("="*70 + "\n")

        # Reset counters
        self.packet_count = 0
        self.captured_packets = []
        self.stats = defaultdict(int)
        self.running = True

        try:
            # Start sniffing
            # Note: This requires root/admin privileges
            sniff(
                iface=None if self.interface == 'eth0' else self.interface,  # None = all interfaces
                prn=self.packet_callback,
                count=count,
                timeout=timeout,
                store=False  # Don't store packets in memory (we handle it)
            )

        except PermissionError:
            logger.error("Permission denied! Packet capture requires administrator privileges.")
            logger.info("\nTo run with proper permissions:")
            logger.info("  Linux: sudo python realtime/packet_sniffer.py")
            logger.info("  Windows: Run terminal as Administrator")
            raise

        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            raise

        finally:
            self.running = False

        logger.info("\n" + "="*70)
        logger.info("CAPTURE COMPLETE")
        logger.info("="*70)
        logger.info(f"Total packets captured: {self.packet_count}")
        logger.info(f"Protocol distribution:")
        for protocol, count in self.stats.items():
            if protocol != 'total':
                percentage = (count / self.stats['total'] * 100) if self.stats['total'] > 0 else 0
                logger.info(f"  {protocol}: {count} ({percentage:.1f}%)")
        logger.info("="*70 + "\n")

        return self.captured_packets

    def get_captured_packets(self):
        """
        Get captured packets

        Returns:
            List of captured packet info
        """
        return self.captured_packets

    def get_statistics(self):
        """
        Get capture statistics

        Returns:
            Dictionary with statistics
        """
        return dict(self.stats)

    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        logger.info("Packet capture stopped")


def test_packet_capture():
    """Test packet capture functionality"""

    logger.info("="*70)
    logger.info("PACKET SNIFFER TEST")
    logger.info("="*70 + "\n")

    # Initialize sniffer
    sniffer = PacketSniffer()

    # Capture 50 packets or 10 seconds (whichever comes first)
    logger.info("Starting packet capture...")
    logger.info("Capturing 50 packets or 10 seconds...\n")

    try:
        packets = sniffer.start_capture(count=50, timeout=10)

        # Display sample packets
        logger.info("\nSample captured packets:")
        logger.info("-" * 70)

        for i, packet in enumerate(packets[:5], 1):
            logger.info(f"\nPacket {i}:")
            logger.info(f"  Time:      {packet['timestamp']}")
            logger.info(f"  Protocol:  {packet['protocol']}")
            logger.info(f"  Source:    {packet['src_ip']}:{packet.get('src_port', 'N/A')}")
            logger.info(f"  Dest:      {packet['dst_ip']}:{packet.get('dst_port', 'N/A')}")
            logger.info(f"  Size:      {packet['packet_size']} bytes")
            if packet.get('flags'):
                logger.info(f"  Flags:     {packet['flags']}")
        logger.info("-" * 70)

        # Statistics
        stats = sniffer.get_statistics()
        logger.info(f"\nCapture Statistics:")
        logger.info(f"  Total packets: {stats.get('total', 0)}")
        logger.info(f"  TCP packets:   {stats.get('TCP', 0)}")
        logger.info(f"  UDP packets:   {stats.get('UDP', 0)}")
        logger.info(f"  ICMP packets:  {stats.get('ICMP', 0)}")

        logger.info("\n✅ Packet capture test successful!")

        return packets

    except PermissionError:
        logger.error("❌ Packet capture requires administrator privileges")
        logger.info("\nPlease run with elevated privileges:")
        logger.info("  sudo python realtime/packet_sniffer.py")
        return []

    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        return []


def main():
    """Main function"""

    import argparse

    parser = argparse.ArgumentParser(description='RT-IDPS Packet Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('-t', '--timeout', type=int, help='Capture timeout in seconds')
    parser.add_argument('--test', action='store_true', help='Run test capture')

    args = parser.parse_args()

    if args.test:
        test_packet_capture()
    else:
        # Regular capture
        sniffer = PacketSniffer(interface=args.interface)
        packets = sniffer.start_capture(count=args.count, timeout=args.timeout)

        logger.info(f"\nCaptured {len(packets)} packets")
        logger.info("Use these packets for feature extraction and detection")


if __name__ == "__main__":
    main()