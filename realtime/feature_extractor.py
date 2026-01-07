"""
RT-IDPS Feature Extraction Module
Extracts ML features from captured network packets
"""

import numpy as np
import pandas as pd
from collections import defaultdict
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import setup_logger

# Setup logger
logger = setup_logger('FeatureExtractor', log_file='logs/feature_extractor.log')


class FeatureExtractor:
    """
    Extract features from network packets for ML detection

    Note: NSL-KDD has complex connection-level features.
    For real-time detection, we use simplified packet-level features.
    """

    def __init__(self):
        """Initialize feature extractor"""
        self.connection_tracker = defaultdict(list)

        # Protocol mappings
        self.protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2}

        # Common service ports
        self.service_map = {
            20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
            25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
            143: 'imap', 443: 'https', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 8080: 'http_proxy'
        }

        logger.info("Feature extractor initialized")

    def extract_packet_features(self, packet_info):
        """
        Extract features from a single packet

        Args:
            packet_info: Dictionary with packet information

        Returns:
            Dictionary with extracted features
        """
        features = {}

        # Basic features
        features['protocol_type'] = self.protocol_map.get(packet_info['protocol'], -1)
        features['src_port'] = packet_info.get('src_port', 0) or 0
        features['dst_port'] = packet_info.get('dst_port', 0) or 0
        features['packet_size'] = packet_info.get('packet_size', 0)
        features['ttl'] = packet_info.get('ttl', 0)

        # Service identification (based on destination port)
        dst_port = features['dst_port']
        features['service'] = self.service_map.get(dst_port, 'other')

        # Flag features (for TCP)
        if packet_info['protocol'] == 'TCP':
            flags = packet_info.get('flags', '')
            features['flag_syn'] = 1 if 'S' in flags else 0
            features['flag_ack'] = 1 if 'A' in flags else 0
            features['flag_fin'] = 1 if 'F' in flags else 0
            features['flag_rst'] = 1 if 'R' in flags else 0
            features['flag_psh'] = 1 if 'P' in flags else 0
            features['flag_urg'] = 1 if 'U' in flags else 0
        else:
            features['flag_syn'] = 0
            features['flag_ack'] = 0
            features['flag_fin'] = 0
            features['flag_rst'] = 0
            features['flag_psh'] = 0
            features['flag_urg'] = 0

        # ICMP features
        if packet_info['protocol'] == 'ICMP':
            features['icmp_type'] = packet_info.get('icmp_type', 0)
            features['icmp_code'] = packet_info.get('icmp_code', 0)
        else:
            features['icmp_type'] = 0
            features['icmp_code'] = 0

        return features

    def extract_connection_features(self, packets_window):
        """
        Extract connection-level features from a window of packets
        Simulates NSL-KDD connection features

        Args:
            packets_window: List of packet info dictionaries

        Returns:
            Dictionary with connection features
        """
        if not packets_window:
            return {}

        features = {}

        # Count features
        features['count'] = len(packets_window)

        # Protocol distribution
        protocols = [p['protocol'] for p in packets_window]
        features['tcp_count'] = protocols.count('TCP')
        features['udp_count'] = protocols.count('UDP')
        features['icmp_count'] = protocols.count('ICMP')

        # Source/Destination statistics
        src_ips = [p['src_ip'] for p in packets_window]
        dst_ips = [p['dst_ip'] for p in packets_window]
        features['unique_src_ips'] = len(set(src_ips))
        features['unique_dst_ips'] = len(set(dst_ips))

        # Port statistics (for TCP/UDP)
        dst_ports = [p.get('dst_port') for p in packets_window if p.get('dst_port')]
        if dst_ports:
            features['unique_dst_ports'] = len(set(dst_ports))
            features['avg_dst_port'] = np.mean(dst_ports)
        else:
            features['unique_dst_ports'] = 0
            features['avg_dst_port'] = 0

        # Size statistics
        sizes = [p['packet_size'] for p in packets_window]
        features['total_bytes'] = sum(sizes)
        features['avg_packet_size'] = np.mean(sizes)
        features['std_packet_size'] = np.std(sizes) if len(sizes) > 1 else 0
        features['min_packet_size'] = min(sizes)
        features['max_packet_size'] = max(sizes)

        # Flag statistics (TCP)
        tcp_packets = [p for p in packets_window if p['protocol'] == 'TCP']
        if tcp_packets:
            syn_count = sum(1 for p in tcp_packets if 'S' in p.get('flags', ''))
            rst_count = sum(1 for p in tcp_packets if 'R' in p.get('flags', ''))
            features['syn_rate'] = syn_count / len(tcp_packets)
            features['rst_rate'] = rst_count / len(tcp_packets)
        else:
            features['syn_rate'] = 0
            features['rst_rate'] = 0

        return features

    def create_feature_vector(self, packet_features, selected_features):
        """
        Create feature vector matching the trained model's expected features

        Args:
            packet_features: Dictionary of extracted features
            selected_features: List of feature names expected by model

        Returns:
            NumPy array of features
        """
        feature_vector = []

        for feature_name in selected_features:
            # Get feature value, default to 0 if not found
            value = packet_features.get(feature_name, 0)

            # Handle categorical features
            if isinstance(value, str):
                # Simple hash-based encoding for strings
                value = hash(value) % 1000

            feature_vector.append(value)

        return np.array(feature_vector, dtype=float)

    def extract_lightweight_features(self, packet_info):
        """
        Extract lightweight features for real-time detection
        These are faster to compute than full NSL-KDD features

        Args:
            packet_info: Packet information dictionary

        Returns:
            Feature dictionary
        """
        features = {}

        # Protocol (categorical -> numeric)
        features['protocol'] = self.protocol_map.get(packet_info['protocol'], -1)

        # Ports
        features['src_port'] = packet_info.get('src_port', 0) or 0
        features['dst_port'] = packet_info.get('dst_port', 0) or 0

        # Port categories (well-known, registered, dynamic)
        dst_port = features['dst_port']
        if dst_port < 1024:
            features['port_category'] = 0  # Well-known
        elif dst_port < 49152:
            features['port_category'] = 1  # Registered
        else:
            features['port_category'] = 2  # Dynamic

        # Packet size features
        size = packet_info.get('packet_size', 0)
        features['packet_size'] = size
        features['size_small'] = 1 if size < 100 else 0
        features['size_medium'] = 1 if 100 <= size < 1000 else 0
        features['size_large'] = 1 if size >= 1000 else 0

        # TTL
        features['ttl'] = packet_info.get('ttl', 64)
        features['ttl_suspicious'] = 1 if features['ttl'] < 30 or features['ttl'] > 128 else 0

        # TCP flags
        if packet_info['protocol'] == 'TCP':
            flags = packet_info.get('flags', '')
            features['syn'] = 1 if 'S' in flags else 0
            features['ack'] = 1 if 'A' in flags else 0
            features['fin'] = 1 if 'F' in flags else 0
            features['rst'] = 1 if 'R' in flags else 0
            features['psh'] = 1 if 'P' in flags else 0

            # Suspicious flag combinations
            features['syn_without_ack'] = 1 if (features['syn'] and not features['ack']) else 0
            features['fin_rst'] = 1 if (features['fin'] and features['rst']) else 0
        else:
            for flag in ['syn', 'ack', 'fin', 'rst', 'psh', 'syn_without_ack', 'fin_rst']:
                features[flag] = 0

        # ICMP
        features['is_icmp'] = 1 if packet_info['protocol'] == 'ICMP' else 0

        # Common attack ports
        attack_ports = [21, 22, 23, 25, 80, 443, 3389, 8080]
        features['targets_attack_port'] = 1 if dst_port in attack_ports else 0

        return features

    def batch_extract(self, packets_list):
        """
        Extract features from multiple packets

        Args:
            packets_list: List of packet info dictionaries

        Returns:
            DataFrame with extracted features
        """
        logger.info(f"Extracting features from {len(packets_list)} packets...")

        features_list = []

        for packet in packets_list:
            features = self.extract_lightweight_features(packet)
            features_list.append(features)

        df = pd.DataFrame(features_list)

        logger.info(f"Extracted {len(df.columns)} features")

        return df


def test_feature_extraction():
    """Test feature extraction"""

    logger.info("="*70)
    logger.info("FEATURE EXTRACTION TEST")
    logger.info("="*70 + "\n")

    # Initialize extractor
    extractor = FeatureExtractor()

    # Sample packets
    sample_packets = [
        {
            'timestamp': '2024-01-01 10:00:00',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': 'TCP',
            'src_port': 50234,
            'dst_port': 443,
            'packet_size': 1024,
            'ttl': 64,
            'flags': 'SA'
        },
        {
            'timestamp': '2024-01-01 10:00:01',
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'protocol': 'UDP',
            'src_port': 53412,
            'dst_port': 53,
            'packet_size': 512,
            'ttl': 64,
            'flags': None
        },
        {
            'timestamp': '2024-01-01 10:00:02',
            'src_ip': '10.0.0.1',
            'dst_ip': '192.168.1.1',
            'protocol': 'ICMP',
            'packet_size': 84,
            'ttl': 128,
            'icmp_type': 8,
            'icmp_code': 0
        }
    ]

    logger.info("Extracting features from sample packets:\n")

    for i, packet in enumerate(sample_packets, 1):
        logger.info(f"Packet {i}: {packet['protocol']} "
                   f"{packet['src_ip']} -> {packet['dst_ip']}")

        features = extractor.extract_lightweight_features(packet)

        logger.info(f"  Extracted {len(features)} features:")
        for key, value in list(features.items())[:10]:
            logger.info(f"    {key}: {value}")
        logger.info("")

    # Batch extraction
    logger.info("Testing batch extraction...")
    df = extractor.batch_extract(sample_packets)

    logger.info(f"\nExtracted features DataFrame:")
    logger.info(f"  Shape: {df.shape}")
    logger.info(f"  Columns: {list(df.columns)}")
    logger.info(f"\n{df.head()}")

    logger.info("\n✅ Feature extraction test successful!")


def main():
    """Main function"""
    test_feature_extraction()


if __name__ == "__main__":
    main()