"""
RT-IDPS Detector Service
Background service for real-time detection with API access
"""

import threading
import time
import queue
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from realtime.packet_sniffer import PacketSniffer
from realtime.feature_extractor import FeatureExtractor
from realtime.prevention import IPBlocker
from ml.hybrid_decision import HybridDetectionEngine
from utils.logger import setup_logger, log_intrusion
from utils.config import PREVENTION_CONFIG

# Setup logger
logger = setup_logger('DetectorService', log_file='logs/detector_service.log')


class DetectorService:
    """
    Background detection service
    Runs continuously and provides API access to detection data
    """

    def __init__(self):
        """Initialize detector service"""
        self.sniffer = PacketSniffer()
        self.extractor = FeatureExtractor()
        self.engine = None
        self.blocker = IPBlocker()

        # Service state
        self.running = False
        self.paused = False
        self.thread = None
        self.capture_error = None

        # Data queues
        self.alert_queue = queue.Queue(maxsize=100)
        self.packet_queue = queue.Queue(maxsize=1000)

        # Statistics
        self.stats = {
            'total_packets': 0,
            'normal': 0,
            'suspicious': 0,
            'malicious': 0,
            'start_time': None,
            'last_update': None,
            'packets_per_second': 0,
            'uptime': 0
        }

        # Recent alerts (last 100)
        self.recent_alerts = []

        # Packet history (last 1000)
        self.packet_history = []

        logger.info("Detector service initialized")

    def load_models(self):
        """Load ML models"""
        logger.info("Loading ML models...")

        try:
            self.engine = HybridDetectionEngine()
            self.engine.load_models()
            logger.info("✓ ML models loaded successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            return False

    def start(self):
        """Start the detection service"""
        if self.running:
            logger.warning("Service is already running")
            return False

        if not self.engine:
            if not self.load_models():
                logger.error("Cannot start service without ML models")
                return False

        logger.info("="*70)
        logger.info("STARTING DETECTOR SERVICE")
        logger.info("="*70 + "\n")

        self.running = True
        self.paused = False
        self.capture_error = None
        self.stats['start_time'] = time.time()

        # Start detection thread
        self.thread = threading.Thread(target=self._detection_loop, daemon=True)
        self.thread.start()

        logger.info("✓ Detector service started")
        return True

    def stop(self):
        """Stop the detection service"""
        if not self.running:
            logger.warning("Service is not running")
            return False

        logger.info("Stopping detector service...")
        self.running = False

        if self.thread:
            self.thread.join(timeout=5)

        logger.info("✓ Detector service stopped")
        return True

    def pause(self):
        """Pause detection"""
        if not self.running:
            return False

        self.paused = True
        logger.info("Detection paused")
        return True

    def resume(self):
        """Resume detection"""
        if not self.running:
            return False

        self.paused = False
        logger.info("Detection resumed")
        return True

    def _detection_loop(self):
        """Main detection loop (runs in background thread)"""
        logger.info("Detection loop started")

        batch_size = 10

        while self.running:
            try:
                if self.paused:
                    time.sleep(1)
                    continue

                # Capture packets
                packets = self.sniffer.start_capture(count=batch_size, timeout=2)

                if not packets:
                    time.sleep(0.5)
                    continue

                # Process each packet
                for packet in packets:
                    if not self.running or self.paused:
                        break

                    self._process_packet(packet)

                # Update statistics
                self._update_stats()

            except PermissionError:
                self.capture_error = (
                    "Packet capture permission denied. Start the dashboard with sudo/root "
                    "or grant packet-capture capabilities to the Python interpreter."
                )
                logger.error(self.capture_error)
                self.running = False
                break
            except RuntimeError as e:
                self.capture_error = str(e)
                logger.error(f"Capture unavailable: {e}")
                self.running = False
                break
            except Exception as e:
                logger.error(f"Error in detection loop: {e}")
                time.sleep(1)

        logger.info("Detection loop stopped")

    def _process_packet(self, packet_info):
        """
        Process a single packet

        Args:
            packet_info: Packet information dictionary
        """
        try:
            # Extract features
            features = self.extractor.extract_lightweight_features(packet_info)

            # Convert to feature vector
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

            # Detect
            decision = self.engine.hybrid_decision(feature_vector)

            # Create packet record
            packet_record = {
                'timestamp': packet_info['timestamp'],
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info['dst_ip'],
                'protocol': packet_info['protocol'],
                'src_port': packet_info.get('src_port'),
                'dst_port': packet_info.get('dst_port'),
                'size': packet_info.get('packet_size', 0),
                'verdict': decision['verdict'],
                'confidence': decision['rf_confidence'],
                'explanation': decision['explanation']
            }

            # Update statistics
            self.stats['total_packets'] += 1

            if decision['verdict'] == 'MALICIOUS':
                self.stats['malicious'] += 1
                self._handle_malicious_traffic(packet_record)
            elif decision['verdict'] == 'SUSPICIOUS':
                self.stats['suspicious'] += 1
                self._handle_suspicious_traffic(packet_record)
            else:
                self.stats['normal'] += 1

            # Add to packet history
            self.packet_history.append(packet_record)
            if len(self.packet_history) > 1000:
                self.packet_history.pop(0)

            # Add to packet queue for real-time updates
            try:
                self.packet_queue.put_nowait(packet_record)
            except queue.Full:
                # Remove oldest
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put_nowait(packet_record)
                except:
                    pass

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _handle_malicious_traffic(self, packet_record):
        """
        Handle malicious traffic detection

        Args:
            packet_record: Packet information
        """
        # Create alert
        alert = {
            'timestamp': packet_record['timestamp'],
            'severity': 'Critical',
            'source_ip': packet_record['src_ip'],
            'dest_ip': packet_record['dst_ip'],
            'attack_type': 'Detected Attack',
            'protocol': packet_record['protocol'],
            'confidence': f"{packet_record['confidence']:.2%}",
            'action': 'Blocked' if PREVENTION_CONFIG['enable_blocking'] else 'Flagged',
            'explanation': packet_record['explanation']
        }

        # Add to recent alerts
        self.recent_alerts.append(alert)
        if len(self.recent_alerts) > 100:
            self.recent_alerts.pop(0)

        # Add to alert queue
        try:
            self.alert_queue.put_nowait(alert)
        except queue.Full:
            try:
                self.alert_queue.get_nowait()
                self.alert_queue.put_nowait(alert)
            except:
                pass

        # Log intrusion
        log_intrusion(
            ip_address=packet_record['src_ip'],
            attack_type=alert['attack_type'],
            action=alert['action'],
            confidence=alert['confidence'],
            extra_info=packet_record['explanation']
        )

        # Block IP if enabled
        if PREVENTION_CONFIG['enable_blocking']:
            self.blocker.block_ip(
                packet_record['src_ip'],
                reason=alert['attack_type'],
                duration=PREVENTION_CONFIG['block_duration']
            )

    def _handle_suspicious_traffic(self, packet_record):
        """
        Handle suspicious traffic detection

        Args:
            packet_record: Packet information
        """
        alert = {
            'timestamp': packet_record['timestamp'],
            'severity': 'Medium',
            'source_ip': packet_record['src_ip'],
            'dest_ip': packet_record['dst_ip'],
            'attack_type': 'Anomaly Detected',
            'protocol': packet_record['protocol'],
            'confidence': 'N/A',
            'action': 'Blocked' if PREVENTION_CONFIG['enable_blocking'] else 'Flagged',
            'explanation': packet_record['explanation']
        }

        # Add to recent alerts
        self.recent_alerts.append(alert)
        if len(self.recent_alerts) > 100:
            self.recent_alerts.pop(0)

        # Add to alert queue
        try:
            self.alert_queue.put_nowait(alert)
        except queue.Full:
            try:
                self.alert_queue.get_nowait()
                self.alert_queue.put_nowait(alert)
            except:
                pass

        # Log intrusion
        log_intrusion(
            ip_address=packet_record['src_ip'],
            attack_type=alert['attack_type'],
            action=alert['action'],
            confidence=alert['confidence'],
            extra_info=packet_record['explanation']
        )

        # Block IP if enabled (for suspicious traffic too)
        if PREVENTION_CONFIG['enable_blocking']:
            self.blocker.block_ip(
                packet_record['src_ip'],
                reason=alert['attack_type'],
                duration=PREVENTION_CONFIG['block_duration']
            )

    def _update_stats(self):
        """Update statistics"""
        self.stats['last_update'] = time.time()

        # Calculate uptime
        if self.stats['start_time']:
            self.stats['uptime'] = time.time() - self.stats['start_time']

        # Calculate packets per second
        if self.stats['uptime'] > 0:
            self.stats['packets_per_second'] = self.stats['total_packets'] / self.stats['uptime']

    def get_statistics(self):
        """
        Get current statistics

        Returns:
            Dictionary with statistics
        """
        total = max(1, self.stats['total_packets'])

        return {
            'total_packets': self.stats['total_packets'],
            'normal': self.stats['normal'],
            'suspicious': self.stats['suspicious'],
            'malicious': self.stats['malicious'],
            'normal_pct': (self.stats['normal'] / total) * 100,
            'suspicious_pct': (self.stats['suspicious'] / total) * 100,
            'malicious_pct': (self.stats['malicious'] / total) * 100,
            'packets_per_second': round(self.stats['packets_per_second'], 2),
            'uptime': round(self.stats['uptime'], 2),
            'status': 'running' if self.running else 'stopped',
            'paused': self.paused,
            'capture_error': self.capture_error,
            'detector_running': self.running,
            'detector_paused': self.paused,
            'threats_detected': self.stats['malicious'] + self.stats['suspicious'],
            'blocked_ips': len(self.blocker.get_blocked_ips())
        }

    def get_recent_alerts(self, limit=10):
        """
        Get recent alerts

        Args:
            limit: Maximum number of alerts to return

        Returns:
            List of recent alerts
        """
        return self.recent_alerts[-limit:] if self.recent_alerts else []

    def get_recent_packets(self, limit=50):
        """
        Get recent packets

        Args:
            limit: Maximum number of packets to return

        Returns:
            List of recent packets
        """
        return self.packet_history[-limit:] if self.packet_history else []

    def get_blocked_ips(self):
        """
        Get blocked IP addresses

        Returns:
            Dictionary of blocked IPs
        """
        return self.blocker.get_blocked_ips()

    def block_ip_manual(self, ip_address, reason="Manual block"):
        """
        Manually block an IP

        Args:
            ip_address: IP to block
            reason: Reason for blocking

        Returns:
            Boolean indicating success
        """
        return self.blocker.block_ip(ip_address, reason=reason)

    def unblock_ip(self, ip_address):
        """
        Unblock an IP

        Args:
            ip_address: IP to unblock

        Returns:
            Boolean indicating success
        """
        return self.blocker.unblock_ip(ip_address)

    def is_running(self):
        """Check if service is running"""
        return self.running

    def is_paused(self):
        """Check if service is paused"""
        return self.paused


# Global service instance
_detector_service = None


def get_detector_service():
    """
    Get the global detector service instance

    Returns:
        DetectorService instance
    """
    global _detector_service

    if _detector_service is None:
        _detector_service = DetectorService()

    return _detector_service


def main():
    """Test the detector service"""

    logger.info("="*70)
    logger.info("DETECTOR SERVICE TEST")
    logger.info("="*70 + "\n")

    # Get service
    service = get_detector_service()

    # Load models
    if not service.load_models():
        logger.error("Failed to load models")
        return

    # Start service
    logger.info("Starting service...")
    service.start()

    try:
        # Run for 60 seconds
        logger.info("Service running for 60 seconds...\n")

        for i in range(12):  # 12 x 5 seconds = 60 seconds
            time.sleep(5)

            # Get stats
            stats = service.get_statistics()
            logger.info(f"Stats: Total={stats['total_packets']} | "
                       f"Normal={stats['normal']} | "
                       f"Suspicious={stats['suspicious']} | "
                       f"Malicious={stats['malicious']}")

            # Get recent alerts
            alerts = service.get_recent_alerts(limit=3)
            if alerts:
                logger.info(f"Recent alerts: {len(alerts)}")

    except KeyboardInterrupt:
        logger.info("\nStopped by user")

    finally:
        # Stop service
        logger.info("\nStopping service...")
        service.stop()

        # Final stats
        final_stats = service.get_statistics()
        logger.info("\n" + "="*70)
        logger.info("FINAL STATISTICS")
        logger.info("="*70)
        logger.info(f"Total packets: {final_stats['total_packets']}")
        logger.info(f"Normal: {final_stats['normal']} ({final_stats['normal_pct']:.1f}%)")
        logger.info(f"Suspicious: {final_stats['suspicious']} ({final_stats['suspicious_pct']:.1f}%)")
        logger.info(f"Malicious: {final_stats['malicious']} ({final_stats['malicious_pct']:.1f}%)")
        logger.info(f"Uptime: {final_stats['uptime']:.2f} seconds")
        logger.info("="*70 + "\n")


if __name__ == "__main__":
    main()
