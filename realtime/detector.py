"""
RT-IDPS Real-time Detector Module
Combines packet capture, feature extraction, and ML detection
"""

import sys
import os
import time
from datetime import datetime
import joblib

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from realtime.packet_sniffer import PacketSniffer
from realtime.feature_extractor import FeatureExtractor
from ml.hybrid_decision import HybridDetectionEngine
from utils.config import DETECTION_CONFIG, FEATURE_NAMES_PATH
from utils.logger import setup_logger, log_intrusion

# Setup logger
logger = setup_logger('RealtimeDetector', log_file='logs/realtime_detector.log')


class RealtimeDetector:
    """
    Real-time Intrusion Detection System
    Captures packets, extracts features, and detects threats
    """

    def __init__(self):
        """Initialize detector"""
        self.sniffer = PacketSniffer()
        self.extractor = FeatureExtractor()
        self.engine = None
        self.running = False

        # Statistics
        self.stats = {
            'total_packets': 0,
            'normal': 0,
            'suspicious': 0,
            'malicious': 0,
            'start_time': None
        }

        logger.info("Real-time detector initialized")

    def load_ml_models(self):
        """Load trained ML models"""
        logger.info("Loading ML models...")

        try:
            self.engine = HybridDetectionEngine()
            self.engine.load_models()

            logger.info("✓ ML models loaded successfully")

        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            logger.info("\nPlease ensure models are trained:")
            logger.info("  python ml/train_rf.py")
            logger.info("  python ml/train_kmeans.py")
            raise

    def detect_packet(self, packet_info):
        """
        Detect threats in a single packet

        Args:
            packet_info: Packet information dictionary

        Returns:
            Detection result dictionary
        """
        try:
            # Extract features
            features = self.extractor.extract_lightweight_features(packet_info)

            # Convert to numpy array (simplified for demo)
            # In production, you'd match exact features from training
            import numpy as np
            feature_vector = np.array(list(features.values()), dtype=float).reshape(1, -1)

            # Pad or truncate to match model's expected features
            # This is a simplified approach - in production, you'd use exact feature mapping
            expected_features = 20  # From feature selection
            if feature_vector.shape[1] < expected_features:
                # Pad with zeros
                padding = np.zeros((1, expected_features - feature_vector.shape[1]))
                feature_vector = np.hstack([feature_vector, padding])
            elif feature_vector.shape[1] > expected_features:
                # Truncate
                feature_vector = feature_vector[:, :expected_features]

            # Run detection
            decision = self.engine.hybrid_decision(feature_vector)

            # Add packet info to decision
            decision['packet'] = {
                'timestamp': packet_info['timestamp'],
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info['dst_ip'],
                'protocol': packet_info['protocol'],
                'src_port': packet_info.get('src_port'),
                'dst_port': packet_info.get('dst_port')
            }

            return decision

        except Exception as e:
            logger.error(f"Detection error: {e}")
            return None

    def process_detection(self, decision):
        """
        Process detection result and take action

        Args:
            decision: Detection result dictionary
        """
        if not decision:
            return

        verdict = decision['verdict']
        packet = decision['packet']

        # Update statistics
        self.stats['total_packets'] += 1

        if verdict == 'MALICIOUS':
            self.stats['malicious'] += 1

            # Log intrusion
            log_intrusion(
                ip_address=packet['src_ip'],
                attack_type='Detected Attack',
                action='Flagged',
                confidence=f"{decision['rf_confidence']:.2%}",
                extra_info=decision['explanation']
            )

            # Log to console
            logger.warning(f"🚨 MALICIOUS TRAFFIC DETECTED!")
            logger.warning(f"   Source: {packet['src_ip']}:{packet.get('src_port', 'N/A')}")
            logger.warning(f"   Destination: {packet['dst_ip']}:{packet.get('dst_port', 'N/A')}")
            logger.warning(f"   Protocol: {packet['protocol']}")
            logger.warning(f"   Confidence: {decision['rf_confidence']:.2%}")
            logger.warning(f"   Reason: {decision['explanation']}\n")

        elif verdict == 'SUSPICIOUS':
            self.stats['suspicious'] += 1

            logger.info(f"⚠️  SUSPICIOUS TRAFFIC")
            logger.info(f"   Source: {packet['src_ip']} -> {packet['dst_ip']}")
            logger.info(f"   Reason: {decision['explanation']}\n")

        else:
            self.stats['normal'] += 1

    def start_monitoring(self, duration=None, packet_count=None):
        """
        Start real-time monitoring

        Args:
            duration: Monitoring duration in seconds (None = infinite)
            packet_count: Number of packets to monitor (None = infinite)
        """
        logger.info("="*70)
        logger.info("STARTING REAL-TIME INTRUSION DETECTION")
        logger.info("="*70)
        logger.info(f"Duration: {duration if duration else 'Infinite'} seconds")
        logger.info(f"Packet count: {packet_count if packet_count else 'Infinite'}")
        logger.info("="*70 + "\n")

        self.running = True
        self.stats['start_time'] = time.time()

        try:
            # Start packet capture in batches
            batch_size = 10
            total_captured = 0

            while self.running:
                # Check if we've reached the limits
                if packet_count and total_captured >= packet_count:
                    break

                if duration:
                    elapsed = time.time() - self.stats['start_time']
                    if elapsed >= duration:
                        break

                # Capture a batch of packets
                remaining = packet_count - total_captured if packet_count else batch_size
                capture_count = min(batch_size, remaining) if packet_count else batch_size

                logger.info(f"Capturing next {capture_count} packets...")
                packets = self.sniffer.start_capture(count=capture_count, timeout=5)

                if not packets:
                    logger.info("No packets captured in this batch")
                    time.sleep(1)
                    continue

                # Detect threats in each packet
                logger.info(f"Analyzing {len(packets)} packets...\n")

                for packet in packets:
                    decision = self.detect_packet(packet)
                    if decision:
                        self.process_detection(decision)

                total_captured += len(packets)

                # Display progress
                self.display_statistics()

        except KeyboardInterrupt:
            logger.info("\n\nMonitoring stopped by user")

        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
            raise

        finally:
            self.running = False
            self.display_final_report()

    def display_statistics(self):
        """Display current statistics"""
        total = self.stats['total_packets']
        if total == 0:
            return

        normal_pct = (self.stats['normal'] / total) * 100
        suspicious_pct = (self.stats['suspicious'] / total) * 100
        malicious_pct = (self.stats['malicious'] / total) * 100

        logger.info("-" * 70)
        logger.info(f"Statistics: Total={total} | "
                   f"Normal={self.stats['normal']} ({normal_pct:.1f}%) | "
                   f"Suspicious={self.stats['suspicious']} ({suspicious_pct:.1f}%) | "
                   f"Malicious={self.stats['malicious']} ({malicious_pct:.1f}%)")
        logger.info("-" * 70 + "\n")

    def display_final_report(self):
        """Display final monitoring report"""
        logger.info("\n" + "="*70)
        logger.info("MONITORING COMPLETE - FINAL REPORT")
        logger.info("="*70)

        duration = time.time() - self.stats['start_time']

        logger.info(f"\nMonitoring Duration: {duration:.2f} seconds")
        logger.info(f"Total Packets Analyzed: {self.stats['total_packets']}")
        logger.info(f"\nDetection Results:")
        logger.info(f"  ✓ Normal:     {self.stats['normal']:6d} ({self.stats['normal']/max(1, self.stats['total_packets'])*100:5.1f}%)")
        logger.info(f"  ⚠ Suspicious:  {self.stats['suspicious']:6d} ({self.stats['suspicious']/max(1, self.stats['total_packets'])*100:5.1f}%)")
        logger.info(f"  🚨 Malicious:  {self.stats['malicious']:6d} ({self.stats['malicious']/max(1, self.stats['total_packets'])*100:5.1f}%)")

        if self.stats['total_packets'] > 0:
            pps = self.stats['total_packets'] / duration
            logger.info(f"\nProcessing Rate: {pps:.2f} packets/second")

        logger.info("="*70 + "\n")

    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        logger.info("Stopping monitoring...")


def test_detector():
    """Test the real-time detector"""

    logger.info("="*70)
    logger.info("REAL-TIME DETECTOR TEST")
    logger.info("="*70 + "\n")

    # Initialize detector
    detector = RealtimeDetector()

    # Load ML models
    try:
        detector.load_ml_models()
    except Exception as e:
        logger.error(f"Cannot run detector without ML models: {e}")
        return

    # Run monitoring for 30 seconds or 50 packets
    logger.info("Starting test monitoring (30 seconds or 50 packets)...\n")

    try:
        detector.start_monitoring(duration=30, packet_count=50)
    except PermissionError:
        logger.error("Packet capture requires administrator privileges")
        logger.info("\nPlease run with elevated privileges:")
        logger.info("  sudo python realtime/detector.py")


def main():
    """Main function"""

    import argparse

    parser = argparse.ArgumentParser(description='RT-IDPS Real-time Detector')
    parser.add_argument('-d', '--duration', type=int, help='Monitoring duration in seconds')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to monitor')
    parser.add_argument('--test', action='store_true', help='Run test')

    args = parser.parse_args()

    if args.test:
        test_detector()
    else:
        # Initialize and run detector
        detector = RealtimeDetector()

        try:
            detector.load_ml_models()
            detector.start_monitoring(duration=args.duration, packet_count=args.count)
        except KeyboardInterrupt:
            logger.info("\nStopped by user")
        except Exception as e:
            logger.error(f"Error: {e}")


if __name__ == "__main__":
    main()