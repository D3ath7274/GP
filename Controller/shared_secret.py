"""
Shared Secret — HMAC Authentication for the UDP Control Channel
================================================================
Both the Controller (verifier) and the Topology script (signer) import
this module to authenticate commands on the out-of-band UDP channel
(port 9999).

Security Properties:
  - HMAC-SHA256 with a pre-shared key prevents command forgery.
  - Timestamp + 30-second window prevents replay attacks.
  - Nonce dedup cache prevents duplicate delivery.

Key Distribution:
  - The key is loaded from the environment variable IPS_HMAC_SECRET.
  - If not set, a random key is generated and saved to /etc/ips/hmac.key
    (or ./hmac.key if /etc/ips is not writable).
  - For multi-VM deployments, copy the key file to both VMs.
  - For single-machine (t530 PoC), both processes share the same filesystem.

Wire Format:
  sign_command("CONTROL:DETECT:ON")
  → "1716735600.123456:a3f8b2c1d4e5...:CONTROL:DETECT:ON"
  
  verify_command(raw_bytes)
  → ("CONTROL:DETECT:ON", "OK")
  → (None, "BAD_HMAC")
  → (None, "REPLAY")
  → (None, "MALFORMED")
"""

import os
import hmac
import time
import hashlib
import secrets
import threading


# =============================================================================
# Key Management
# =============================================================================

_KEY_ENV_VAR = 'IPS_HMAC_SECRET'
_KEY_FILE_PATHS = ['/etc/ips/hmac.key', './hmac.key']
_REPLAY_WINDOW_SEC = 30
_NONCE_CACHE_MAX = 10000

_shared_secret = None
_lock = threading.Lock()


def _load_or_generate_key():
    """Load the HMAC key from environment or file, or generate a new one."""
    global _shared_secret
    if _shared_secret is not None:
        return _shared_secret

    with _lock:
        if _shared_secret is not None:
            return _shared_secret

        # 1. Try environment variable
        env_key = os.environ.get(_KEY_ENV_VAR, '').strip()
        if env_key:
            _shared_secret = env_key.encode('utf-8')
            return _shared_secret

        # 2. Try reading from key file
        for key_path in _KEY_FILE_PATHS:
            try:
                if os.path.exists(key_path):
                    with open(key_path, 'r') as f:
                        file_key = f.read().strip()
                    if file_key:
                        _shared_secret = file_key.encode('utf-8')
                        return _shared_secret
            except (IOError, OSError):
                continue

        # 3. Generate a new key and save it
        new_key = secrets.token_hex(32)  # 256-bit key
        for key_path in _KEY_FILE_PATHS:
            try:
                os.makedirs(os.path.dirname(key_path) or '.', exist_ok=True)
                with open(key_path, 'w') as f:
                    f.write(new_key)
                # Restrict permissions (owner-only read/write)
                try:
                    os.chmod(key_path, 0o600)
                except (OSError, AttributeError):
                    pass  # Windows doesn't support chmod the same way
                _shared_secret = new_key.encode('utf-8')
                return _shared_secret
            except (IOError, OSError):
                continue

        # 4. Fallback: use the key in memory only (not persisted)
        _shared_secret = new_key.encode('utf-8')
        return _shared_secret


def get_secret():
    """Return the shared secret as bytes."""
    return _load_or_generate_key()


# =============================================================================
# Nonce / Replay Cache
# =============================================================================

_seen_nonces = set()
_seen_nonces_lock = threading.Lock()


def _prune_nonces():
    """Remove old nonces if cache is too large."""
    global _seen_nonces
    if len(_seen_nonces) > _NONCE_CACHE_MAX:
        _seen_nonces = set()


# =============================================================================
# Signing (used by Topology VM)
# =============================================================================

def sign_command(command):
    """
    Sign a command string for transmission over the UDP channel.

    Args:
        command: The plaintext command string (e.g., "CONTROL:DETECT:ON")

    Returns:
        Signed message string: "timestamp:hmac_hex:command"
    """
    secret = get_secret()
    timestamp = f"{time.time():.6f}"
    payload = f"{timestamp}:{command}"
    mac = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{timestamp}:{mac}:{command}"


# =============================================================================
# Verification (used by Controller VM)
# =============================================================================

def verify_command(raw_data):
    """
    Verify an HMAC-signed command received on the UDP channel.

    Args:
        raw_data: Raw bytes or string received from the UDP socket.

    Returns:
        Tuple of (command_string, status) where status is one of:
          'OK'        — Valid signature, within replay window, not a duplicate.
          'BAD_HMAC'  — Signature does not match (tampered or wrong key).
          'REPLAY'    — Timestamp outside the 30-second replay window.
          'DUPLICATE' — This exact signed message was already processed.
          'MALFORMED' — Message format is not "timestamp:hmac:command".
    """
    if isinstance(raw_data, bytes):
        raw_data = raw_data.decode('utf-8', errors='ignore').strip()

    # Parse: "timestamp:hmac_hex:command"
    parts = raw_data.split(':', 2)
    if len(parts) < 3:
        return None, 'MALFORMED'

    timestamp_str = parts[0]
    received_mac = parts[1]
    command = parts[2]

    # Validate timestamp format
    try:
        msg_time = float(timestamp_str)
    except (ValueError, TypeError):
        return None, 'MALFORMED'

    # Check replay window
    now = time.time()
    age = abs(now - msg_time)
    if age > _REPLAY_WINDOW_SEC:
        return None, 'REPLAY'

    # Check for duplicate (nonce = full signed message)
    nonce = f"{timestamp_str}:{received_mac}"
    with _seen_nonces_lock:
        if nonce in _seen_nonces:
            return None, 'DUPLICATE'
        _seen_nonces.add(nonce)
        _prune_nonces()

    # Verify HMAC
    secret = get_secret()
    payload = f"{timestamp_str}:{command}"
    expected_mac = hmac.new(secret, payload.encode('utf-8'), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(received_mac, expected_mac):
        return None, 'BAD_HMAC'

    return command, 'OK'


# =============================================================================
# Utility
# =============================================================================

def set_secret(secret_bytes):
    """
    Override the shared secret (for testing or programmatic key injection).
    
    Args:
        secret_bytes: The secret as bytes.
    """
    global _shared_secret
    with _lock:
        _shared_secret = secret_bytes


# =============================================================================
# Self-Test
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  Shared Secret Module — Self-Test")
    print("=" * 60)

    # Force a known key for testing
    set_secret(b'test-secret-key-12345')

    # Test 1: Sign and verify
    cmd = "CONTROL:DETECT:ON"
    signed = sign_command(cmd)
    print(f"\n  Original:  {cmd}")
    print(f"  Signed:    {signed[:80]}...")

    result, status = verify_command(signed)
    assert status == 'OK', f"Expected OK, got {status}"
    assert result == cmd, f"Expected '{cmd}', got '{result}'"
    print(f"  Verified:  {result} → {status} ✅")

    # Test 2: Duplicate detection
    result2, status2 = verify_command(signed)
    assert status2 == 'DUPLICATE', f"Expected DUPLICATE, got {status2}"
    print(f"  Duplicate: → {status2} ✅")

    # Test 3: Tampered message
    tampered = signed.replace('DETECT:ON', 'DETECT:OFF')
    result3, status3 = verify_command(tampered)
    assert status3 == 'BAD_HMAC', f"Expected BAD_HMAC, got {status3}"
    print(f"  Tampered:  → {status3} ✅")

    # Test 4: Replay (old timestamp)
    old_signed = f"1000000000.000000:fakemac:CONTROL:DETECT:ON"
    result4, status4 = verify_command(old_signed)
    assert status4 == 'REPLAY', f"Expected REPLAY, got {status4}"
    print(f"  Replay:    → {status4} ✅")

    # Test 5: Malformed
    result5, status5 = verify_command("garbage")
    assert status5 == 'MALFORMED', f"Expected MALFORMED, got {status5}"
    print(f"  Malformed: → {status5} ✅")

    # Test 6: Complex command with colons
    cmd6 = "LABEL_OVERRIDE:10.0.0.3:Port Scan"
    signed6 = sign_command(cmd6)
    result6, status6 = verify_command(signed6)
    assert status6 == 'OK' and result6 == cmd6
    print(f"  Complex:   {result6} → {status6} ✅")

    print(f"\n  All tests passed ✅")
    print("=" * 60)
