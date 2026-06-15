"""
Controller Watchdog — Health Monitoring & Auto-Restart
========================================================
Standalone process that monitors the Ryu controller's health
and automatically restarts it on failure (crash, OOM, hang).

Designed for the HP t530 thin client deployment where the controller
must stay up 24/7 without manual intervention.

Health Check Mechanism:
    The controller writes a timestamp to /tmp/ips_heartbeat every 3 seconds.
    The watchdog reads this file every 5 seconds. If the timestamp is
    stale (>10 seconds old), the controller is considered dead.

Usage:
    # Start as the primary entry point (instead of ryu-manager directly):
    python3 watchdog.py

    # Or as a systemd service:
    # [Service]
    # ExecStart=/usr/bin/python3 /path/to/watchdog.py
    # Restart=always
"""

import os
import sys
import time
import signal
import subprocess
import threading
from datetime import datetime


# =============================================================================
# Configuration
# =============================================================================

HEARTBEAT_FILE = '/tmp/ips_heartbeat'
CHECK_INTERVAL = 5       # Seconds between health checks
STALE_THRESHOLD = 15     # Seconds before heartbeat is considered stale
MAX_RESTARTS = 5         # Maximum restarts before giving up
RESTART_COOLDOWN = 10    # Seconds to wait before restarting
CONTROLLER_SCRIPT = 'Controller.py'
RYU_COMMAND = ['ryu-manager', CONTROLLER_SCRIPT]

WATCHDOG_LOG = '/var/log/ips/watchdog.log'


# =============================================================================
# Watchdog
# =============================================================================

class ControllerWatchdog:
    """
    Monitors and auto-restarts the Ryu SDN controller.

    Args:
        controller_dir: Directory containing Controller.py
        max_restarts: Maximum consecutive restarts before giving up.
        heartbeat_file: Path to the heartbeat file.
    """

    def __init__(self, controller_dir=None, max_restarts=MAX_RESTARTS,
                 heartbeat_file=HEARTBEAT_FILE):
        self.controller_dir = controller_dir or os.path.dirname(
            os.path.abspath(__file__)
        )
        self.max_restarts = max_restarts
        self.heartbeat_file = heartbeat_file
        self._process = None
        self._restart_count = 0
        self._total_restarts = 0
        self._running = False
        self._start_time = None

        # Setup log directory
        log_dir = os.path.dirname(WATCHDOG_LOG)
        try:
            os.makedirs(log_dir, exist_ok=True)
        except OSError:
            pass

    def _log(self, level, msg):
        """Log to both stdout and the watchdog log file."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{timestamp}] [{level}] {msg}"
        print(line)
        try:
            with open(WATCHDOG_LOG, 'a') as f:
                f.write(line + '\n')
        except (IOError, OSError):
            pass

    def _start_controller(self):
        """Start the Ryu controller as a subprocess."""
        self._log('INFO', f"Starting controller: {' '.join(RYU_COMMAND)}")
        self._log('INFO', f"Working directory: {self.controller_dir}")

        try:
            self._process = subprocess.Popen(
                RYU_COMMAND,
                cwd=self.controller_dir,
                stdout=sys.stdout,
                stderr=sys.stderr,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
            )
            self._start_time = time.time()
            self._log('INFO', f"Controller started (PID: {self._process.pid})")
            return True
        except FileNotFoundError:
            self._log('ERROR', "ryu-manager not found! Install with: pip install ryu")
            return False
        except Exception as e:
            self._log('ERROR', f"Failed to start controller: {e}")
            return False

    def _stop_controller(self):
        """Gracefully stop the controller."""
        if self._process and self._process.poll() is None:
            self._log('INFO', f"Stopping controller (PID: {self._process.pid})")
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(self._process.pid), signal.SIGTERM)
                else:
                    self._process.terminate()
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._log('WARN', "Controller didn't stop gracefully, killing...")
                self._process.kill()
                self._process.wait()
            except (ProcessLookupError, OSError):
                pass
            self._log('INFO', "Controller stopped")

    def _check_heartbeat(self):
        """
        Check if the heartbeat file is fresh.
        Returns True if healthy, False if stale/missing.
        """
        try:
            if not os.path.exists(self.heartbeat_file):
                return False
            with open(self.heartbeat_file, 'r') as f:
                last_beat = float(f.read().strip())
            age = time.time() - last_beat
            return age < STALE_THRESHOLD
        except (ValueError, IOError, OSError):
            return False

    def _check_process_alive(self):
        """Check if the controller process is still running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    def run(self):
        """Main watchdog loop."""
        self._running = True
        self._log('INFO', "=" * 60)
        self._log('INFO', "  IPS Controller Watchdog Started")
        self._log('INFO', f"  Max restarts: {self.max_restarts}")
        self._log('INFO', f"  Heartbeat file: {self.heartbeat_file}")
        self._log('INFO', f"  Check interval: {CHECK_INTERVAL}s")
        self._log('INFO', f"  Stale threshold: {STALE_THRESHOLD}s")
        self._log('INFO', "=" * 60)

        # Initial start
        if not self._start_controller():
            self._log('ERROR', "Failed to start controller. Exiting.")
            return

        # Give the controller time to start up and begin heartbeating
        time.sleep(STALE_THRESHOLD)

        while self._running:
            time.sleep(CHECK_INTERVAL)

            # Check 1: Is the process alive?
            if not self._check_process_alive():
                exit_code = self._process.returncode if self._process else 'unknown'
                self._log('ERROR', f"Controller process DIED (exit code: {exit_code})")
                self._attempt_restart('process_died')
                continue

            # Check 2: Is the heartbeat fresh?
            if not self._check_heartbeat():
                uptime = time.time() - (self._start_time or time.time())
                # Only check heartbeat after initial startup period
                if uptime > STALE_THRESHOLD * 2:
                    self._log('WARN', "Heartbeat STALE — controller may be hung")
                    self._attempt_restart('heartbeat_stale')
                    continue

            # Healthy — reset consecutive restart counter
            if self._restart_count > 0:
                self._log('INFO', f"Controller healthy — resetting restart counter "
                                  f"(was {self._restart_count})")
                self._restart_count = 0

    def _attempt_restart(self, reason):
        """Attempt to restart the controller with retry limits."""
        self._restart_count += 1
        self._total_restarts += 1

        if self._restart_count > self.max_restarts:
            self._log('ERROR',
                       f"Max restarts ({self.max_restarts}) exceeded! "
                       f"Reason: {reason}. GIVING UP — manual intervention required.")
            self._running = False
            return

        self._log('WARN',
                   f"Restarting controller (attempt {self._restart_count}/{self.max_restarts}, "
                   f"reason: {reason}, total restarts: {self._total_restarts})")

        self._stop_controller()
        time.sleep(RESTART_COOLDOWN)

        # Clean up stale heartbeat
        try:
            if os.path.exists(self.heartbeat_file):
                os.remove(self.heartbeat_file)
        except OSError:
            pass

        if not self._start_controller():
            self._log('ERROR', "Failed to restart controller!")
            return

        # Wait for startup
        time.sleep(STALE_THRESHOLD)

    def stop(self):
        """Stop the watchdog and the controller."""
        self._running = False
        self._stop_controller()
        self._log('INFO', "Watchdog stopped")


# =============================================================================
# Heartbeat Writer (imported by Controller.py)
# =============================================================================

def start_heartbeat_thread(interval=3, heartbeat_file=HEARTBEAT_FILE):
    """
    Start a background thread that writes the current timestamp
    to the heartbeat file at the specified interval.

    Called by Controller.py at startup to enable watchdog monitoring.
    """
    def _heartbeat_loop():
        while True:
            try:
                with open(heartbeat_file, 'w') as f:
                    f.write(str(time.time()))
            except (IOError, OSError):
                pass
            time.sleep(interval)

    t = threading.Thread(target=_heartbeat_loop, name='Heartbeat', daemon=True)
    t.start()
    return t


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='IPS Controller Watchdog')
    parser.add_argument('--controller-dir', default=None,
                        help='Directory containing Controller.py')
    parser.add_argument('--max-restarts', type=int, default=MAX_RESTARTS,
                        help=f'Maximum restarts (default: {MAX_RESTARTS})')
    args = parser.parse_args()

    watchdog = ControllerWatchdog(
        controller_dir=args.controller_dir,
        max_restarts=args.max_restarts,
    )

    # Handle Ctrl+C gracefully
    def _signal_handler(sig, frame):
        print("\nShutting down watchdog...")
        watchdog.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    watchdog.run()
