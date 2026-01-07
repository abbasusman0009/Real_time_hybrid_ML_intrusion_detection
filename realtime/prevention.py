"""
RT-IDPS Prevention Module
Automatically blocks malicious IP addresses
"""

import sys
import os
import subprocess
import platform
from datetime import datetime, timedelta
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import PREVENTION_CONFIG, LOGS_DIR
from utils.logger import setup_logger

# Setup logger
logger = setup_logger('Prevention', log_file='logs/prevention.log')


class IPBlocker:
    """
    IP address blocking system
    Uses iptables on Linux or simulated blocking on Windows
    """

    def __init__(self):
        """Initialize IP blocker"""
        self.os_type = platform.system()
        self.blocked_ips = {}
        self.blocked_ips_file = LOGS_DIR / 'blocked_ips.json'

        # Load previously blocked IPs
        self.load_blocked_ips()

        logger.info(f"IP Blocker initialized on {self.os_type}")

    def load_blocked_ips(self):
        """Load blocked IPs from file"""
        try:
            if self.blocked_ips_file.exists():
                with open(self.blocked_ips_file, 'r') as f:
                    self.blocked_ips = json.load(f)
                logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from file")
        except Exception as e:
            logger.error(f"Error loading blocked IPs: {e}")
            self.blocked_ips = {}

    def save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            os.makedirs(LOGS_DIR, exist_ok=True)
            with open(self.blocked_ips_file, 'w') as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving blocked IPs: {e}")

    def block_ip(self, ip_address, reason="Malicious activity", duration=None):
        """
        Block an IP address

        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None = use config default)

        Returns:
            Boolean indicating success
        """
        # Check if already blocked
        if ip_address in self.blocked_ips:
            logger.info(f"IP {ip_address} is already blocked")
            return True

        # Check max blocked IPs
        if len(self.blocked_ips) >= PREVENTION_CONFIG['max_blocked_ips']:
            logger.warning(f"Maximum blocked IPs reached ({PREVENTION_CONFIG['max_blocked_ips']})")
            return False

        # Set duration
        if duration is None:
            duration = PREVENTION_CONFIG['block_duration']

        # Calculate expiry
        expiry_time = datetime.now() + timedelta(seconds=duration)

        logger.info("="*70)
        logger.info(f"🚫 BLOCKING IP ADDRESS")
        logger.info("="*70)
        logger.info(f"IP Address: {ip_address}")
        logger.info(f"Reason: {reason}")
        logger.info(f"Duration: {duration} seconds")
        logger.info(f"Expires: {expiry_time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70 + "\n")

        # Perform actual blocking
        if PREVENTION_CONFIG['enable_blocking']:
            if self.os_type == "Linux" and PREVENTION_CONFIG['use_iptables']:
                success = self._block_ip_iptables(ip_address)
            else:
                success = self._block_ip_simulated(ip_address)

            if not success:
                logger.error(f"Failed to block IP {ip_address}")
                return False

        # Store blocked IP
        self.blocked_ips[ip_address] = {
            'reason': reason,
            'blocked_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'expires_at': expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': duration
        }

        self.save_blocked_ips()

        logger.info(f"✅ IP {ip_address} blocked successfully")
        return True

    def _block_ip_iptables(self, ip_address):
        """
        Block IP using iptables (Linux only)

        Args:
            ip_address: IP to block

        Returns:
            Boolean indicating success
        """
        try:
            # Add iptables rule
            cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            logger.info(f"iptables rule added: {' '.join(cmd)}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"iptables command failed: {e.stderr}")
            return False

        except Exception as e:
            logger.error(f"Error executing iptables: {e}")
            return False

    def _block_ip_simulated(self, ip_address):
        """
        Simulated IP blocking (for testing/Windows)

        Args:
            ip_address: IP to block

        Returns:
            Boolean (always True)
        """
        logger.info(f"[SIMULATED] Blocking IP {ip_address}")
        logger.info("(Real blocking disabled or not available on this platform)")
        return True

    def unblock_ip(self, ip_address):
        """
        Unblock an IP address

        Args:
            ip_address: IP address to unblock

        Returns:
            Boolean indicating success
        """
        if ip_address not in self.blocked_ips:
            logger.info(f"IP {ip_address} is not in blocked list")
            return True

        logger.info(f"Unblocking IP {ip_address}...")

        # Remove from firewall
        if PREVENTION_CONFIG['enable_blocking']:
            if self.os_type == "Linux" and PREVENTION_CONFIG['use_iptables']:
                self._unblock_ip_iptables(ip_address)
            else:
                self._unblock_ip_simulated(ip_address)

        # Remove from list
        del self.blocked_ips[ip_address]
        self.save_blocked_ips()

        logger.info(f"✅ IP {ip_address} unblocked")
        return True

    def _unblock_ip_iptables(self, ip_address):
        """
        Unblock IP using iptables

        Args:
            ip_address: IP to unblock
        """
        try:
            cmd = ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP']
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"iptables rule removed for {ip_address}")
        except Exception as e:
            logger.error(f"Error removing iptables rule: {e}")

    def _unblock_ip_simulated(self, ip_address):
        """Simulated unblocking"""
        logger.info(f"[SIMULATED] Unblocking IP {ip_address}")

    def check_expired_blocks(self):
        """Check and remove expired blocks"""
        now = datetime.now()
        expired_ips = []

        for ip, info in self.blocked_ips.items():
            expires_at = datetime.strptime(info['expires_at'], '%Y-%m-%d %H:%M:%S')
            if now >= expires_at:
                expired_ips.append(ip)

        # Unblock expired IPs
        for ip in expired_ips:
            logger.info(f"Block expired for {ip}")
            self.unblock_ip(ip)

        return len(expired_ips)

    def get_blocked_ips(self):
        """
        Get list of currently blocked IPs

        Returns:
            Dictionary of blocked IPs with info
        """
        return self.blocked_ips

    def is_blocked(self, ip_address):
        """
        Check if IP is blocked

        Args:
            ip_address: IP to check

        Returns:
            Boolean
        """
        return ip_address in self.blocked_ips

    def get_statistics(self):
        """
        Get blocking statistics

        Returns:
            Dictionary with statistics
        """
        return {
            'total_blocked': len(self.blocked_ips),
            'max_capacity': PREVENTION_CONFIG['max_blocked_ips'],
            'capacity_used': f"{len(self.blocked_ips) / PREVENTION_CONFIG['max_blocked_ips'] * 100:.1f}%"
        }


def test_prevention():
    """Test IP blocking functionality"""

    logger.info("="*70)
    logger.info("IP BLOCKING TEST")
    logger.info("="*70 + "\n")

    # Initialize blocker
    blocker = IPBlocker()

    # Test blocking
    test_ip = "192.168.1.100"

    logger.info(f"Test 1: Blocking IP {test_ip}")
    success = blocker.block_ip(test_ip, reason="Test block", duration=300)

    if success:
        logger.info("✓ Block successful\n")
    else:
        logger.error("✗ Block failed\n")

    # Check if blocked
    logger.info(f"Test 2: Checking if {test_ip} is blocked")
    is_blocked = blocker.is_blocked(test_ip)
    logger.info(f"✓ Is blocked: {is_blocked}\n")

    # Get blocked IPs
    logger.info("Test 3: Getting blocked IPs list")
    blocked = blocker.get_blocked_ips()
    logger.info(f"✓ Total blocked IPs: {len(blocked)}")
    for ip, info in blocked.items():
        logger.info(f"  - {ip}: {info['reason']}")
    logger.info("")

    # Statistics
    logger.info("Test 4: Getting statistics")
    stats = blocker.get_statistics()
    for key, value in stats.items():
        logger.info(f"  {key}: {value}")
    logger.info("")

    # Unblock
    logger.info(f"Test 5: Unblocking {test_ip}")
    success = blocker.unblock_ip(test_ip)
    if success:
        logger.info("✓ Unblock successful\n")

    logger.info("="*70)
    logger.info("PREVENTION TEST COMPLETE")
    logger.info("="*70)
    logger.info("\nNote: Actual iptables blocking requires:")
    logger.info("  1. Linux operating system")
    logger.info("  2. sudo privileges")
    logger.info("  3. use_iptables=True in config")
    logger.info("\nOtherwise, simulated blocking is used for testing.")
    logger.info("="*70 + "\n")


def main():
    """Main function"""
    test_prevention()


if __name__ == "__main__":
    main()