"""
Incident Logger — Persistent Security Event Log
==================================================
Thread-safe JSON Lines (JSONL) logger for all security-relevant events:
quarantines, contract violations, watchdog restarts, manual overrides, etc.

Output Format (one JSON object per line):
    {"timestamp": "...", "event": "QUARANTINE", "src_ip": "10.0.0.5", ...}

Usage:
    from incident_logger import IncidentLogger
    logger = IncidentLogger('/var/log/ips/incidents.jsonl')
    logger.log('QUARANTINE', src_ip='10.0.0.5', device='TempSensor',
               reason='contract_violation', details='SSH on port 22',
               action='DROP rule installed')
"""

import os
import json
import time
import threading
from datetime import datetime


class IncidentLogger:
    """
    Append-only incident log in JSON Lines format.

    Args:
        log_path: Path to the JSONL log file. Parent directories
                  are created automatically if they don't exist.
    """

    def __init__(self, log_path='/var/log/ips/incidents.jsonl'):
        self.log_path = log_path
        self._lock = threading.Lock()
        self._event_count = 0

        # Ensure parent directory exists
        log_dir = os.path.dirname(log_path)
        if log_dir:
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError:
                # Fallback to current directory if /var/log is not writable
                self.log_path = os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    'incidents.jsonl'
                )
                os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log(self, event_type, **kwargs):
        """
        Log a security incident.

        Args:
            event_type: One of 'QUARANTINE', 'CONTRACT_VIOLATION', 'BLOCK',
                        'UNBLOCK', 'ESCALATION', 'WATCHDOG_RESTART',
                        'ML_DETECTION', 'RETRAIN', 'HMAC_REJECT', 'RATE_LIMIT'.
            **kwargs: Additional fields to include in the log entry.
                      Common fields: src_ip, device, reason, details, action,
                      attack_type, confidence, model_version.
        """
        entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event_type,
            'epoch': time.time(),
        }
        entry.update(kwargs)

        with self._lock:
            try:
                with open(self.log_path, 'a', encoding='utf-8') as f:
                    f.write(json.dumps(entry, default=str) + '\n')
                self._event_count += 1
            except Exception as e:
                # Last resort: print to stdout if file write fails
                print(f"[INCIDENT_LOG_ERROR] Failed to write: {e}")
                print(f"[INCIDENT_LOG] {json.dumps(entry, default=str)}")

    def get_recent(self, n=50):
        """Read the last N incident entries (for STATUS command)."""
        entries = []
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                for line in lines[-n:]:
                    try:
                        entries.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        return entries

    def get_count(self):
        """Return total number of logged incidents."""
        return self._event_count

    @property
    def path(self):
        return self.log_path


# Module-level singleton (lazy initialization)
_default_logger = None
_default_lock = threading.Lock()


def get_incident_logger(log_path=None):
    """Get or create the singleton incident logger."""
    global _default_logger
    if _default_logger is None:
        with _default_lock:
            if _default_logger is None:
                path = log_path or '/var/log/ips/incidents.jsonl'
                _default_logger = IncidentLogger(path)
    return _default_logger


# =============================================================================
# Self-Test
# =============================================================================

if __name__ == '__main__':
    import tempfile
    print("=" * 60)
    print("  Incident Logger — Self-Test")
    print("=" * 60)

    # Use a temp file for testing
    test_path = os.path.join(tempfile.gettempdir(), 'test_incidents.jsonl')
    if os.path.exists(test_path):
        os.remove(test_path)

    logger = IncidentLogger(test_path)

    # Test 1: Log a quarantine event
    logger.log('QUARANTINE',
               src_ip='10.0.0.5',
               device='TempSensor',
               reason='contract_violation',
               details='SSH on port 22 (not in allowed_dst_ports)',
               action='DROP rule installed on 3 switches')
    print(f"\n  Logged QUARANTINE event ✅")

    # Test 2: Log a block event
    logger.log('BLOCK',
               src_ip='10.0.0.3',
               device='h1',
               attack_type='SYN Flood',
               confidence=0.97,
               action='DROP rule for 30s')
    print(f"  Logged BLOCK event ✅")

    # Test 3: Log an ML detection
    logger.log('ML_DETECTION',
               src_ip='10.0.0.6',
               device='Cam',
               attack_type='ICMP Flood',
               confidence=0.89,
               model_version='v1.0')
    print(f"  Logged ML_DETECTION event ✅")

    # Test 4: Read back
    entries = logger.get_recent(10)
    assert len(entries) == 3, f"Expected 3 entries, got {len(entries)}"
    assert entries[0]['event'] == 'QUARANTINE'
    assert entries[1]['src_ip'] == '10.0.0.3'
    assert entries[2]['confidence'] == 0.89
    print(f"\n  Read back {len(entries)} entries ✅")

    # Test 5: Event count
    assert logger.get_count() == 3
    print(f"  Event count: {logger.get_count()} ✅")

    # Cleanup
    os.remove(test_path)
    print(f"\n  All tests passed ✅")
    print("=" * 60)
