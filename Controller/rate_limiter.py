"""
Token Bucket Rate Limiter — UDP Command Channel Protection
============================================================
Prevents command-flooding attacks on the UDP port 9999 control channel.
Each source IP gets an independent token bucket with configurable
rate (tokens/sec) and burst (max tokens).

Usage:
    limiter = TokenBucket(rate=10, burst=20)

    if limiter.allow(sender_ip):
        process_command(...)
    else:
        log("Rate exceeded for %s", sender_ip)

Design:
    - Token Bucket algorithm: O(1) per check, no background threads.
    - Per-IP isolation: one attacker's flood doesn't affect legitimate senders.
    - Violation tracking: logs a pivot-attack warning after N violations.
    - Auto-cleanup: stale buckets pruned every 60 seconds.
"""

import time
import threading


class TokenBucket:
    """
    Per-IP token bucket rate limiter.

    Args:
        rate: Tokens refilled per second (sustained rate).
        burst: Maximum tokens in the bucket (peak burst capacity).
        violation_threshold: After this many violations from one IP,
                             log a pivot-attack warning.
        cleanup_interval: Seconds between stale-bucket cleanup sweeps.
    """

    def __init__(self, rate=10, burst=20, violation_threshold=100,
                 cleanup_interval=60):
        self.rate = rate
        self.burst = burst
        self.violation_threshold = violation_threshold
        self.cleanup_interval = cleanup_interval

        # Per-IP state: {ip: {'tokens': float, 'last_refill': float}}
        self._buckets = {}
        # Per-IP violation counter: {ip: int}
        self._violations = {}
        # IPs that have already triggered a pivot warning (log once)
        self._warned_ips = set()

        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def allow(self, ip):
        """
        Check if a command from the given IP should be allowed.

        Returns:
            True if allowed (token consumed), False if rate exceeded.
        """
        now = time.time()

        with self._lock:
            # Periodic cleanup of stale buckets
            if now - self._last_cleanup > self.cleanup_interval:
                self._cleanup(now)

            bucket = self._buckets.get(ip)
            if bucket is None:
                # First command from this IP — create bucket with full burst
                self._buckets[ip] = {
                    'tokens': self.burst - 1,  # Consume 1 token for this request
                    'last_refill': now,
                }
                return True

            # Refill tokens based on elapsed time
            elapsed = now - bucket['last_refill']
            bucket['tokens'] = min(
                self.burst,
                bucket['tokens'] + elapsed * self.rate
            )
            bucket['last_refill'] = now

            if bucket['tokens'] >= 1.0:
                bucket['tokens'] -= 1.0
                return True
            else:
                # Rate exceeded — track violation
                self._violations[ip] = self._violations.get(ip, 0) + 1
                return False

    def get_violations(self, ip):
        """Return the number of rate violations for a given IP."""
        with self._lock:
            return self._violations.get(ip, 0)

    def is_pivot_attack(self, ip):
        """
        Check if an IP has exceeded the violation threshold.
        Returns True at most once per IP (to avoid log flooding).
        """
        with self._lock:
            violations = self._violations.get(ip, 0)
            if violations >= self.violation_threshold and ip not in self._warned_ips:
                self._warned_ips.add(ip)
                return True
            return False

    def get_stats(self):
        """Return a summary of rate limiter state (for STATUS command)."""
        with self._lock:
            return {
                'active_buckets': len(self._buckets),
                'total_violations': sum(self._violations.values()),
                'violating_ips': {
                    ip: count for ip, count in self._violations.items()
                    if count > 0
                },
            }

    def _cleanup(self, now):
        """Remove buckets that haven't been used in 5 minutes."""
        stale_cutoff = now - 300  # 5 minutes
        stale_ips = [
            ip for ip, bucket in self._buckets.items()
            if bucket['last_refill'] < stale_cutoff
        ]
        for ip in stale_ips:
            del self._buckets[ip]
            self._violations.pop(ip, None)
            self._warned_ips.discard(ip)
        self._last_cleanup = now


# =============================================================================
# Self-Test
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  Token Bucket Rate Limiter — Self-Test")
    print("=" * 60)

    # Test 1: Basic allow/deny
    tb = TokenBucket(rate=10, burst=5)
    results = [tb.allow('10.0.0.1') for _ in range(10)]
    allowed = sum(results)
    print(f"\n  Burst test (burst=5, 10 requests): {allowed} allowed, {10-allowed} denied")
    assert results[:5] == [True] * 5, "First 5 should be allowed"
    assert not all(results[5:]), "Some after burst should be denied"
    print(f"  → PASS ✅")

    # Test 2: Refill after waiting
    import time as _t
    _t.sleep(0.3)  # Wait for ~3 tokens to refill (10/sec * 0.3s)
    refill_results = [tb.allow('10.0.0.1') for _ in range(5)]
    refill_allowed = sum(refill_results)
    print(f"\n  Refill test (waited 0.3s at rate=10/s): {refill_allowed} allowed")
    assert refill_allowed >= 2, "Should have refilled at least 2 tokens"
    print(f"  → PASS ✅")

    # Test 3: Per-IP isolation
    tb2 = TokenBucket(rate=10, burst=3)
    # IP A uses all burst
    for _ in range(3):
        tb2.allow('10.0.0.1')
    assert not tb2.allow('10.0.0.1'), "IP A should be denied"
    # IP B should still have full burst
    assert tb2.allow('10.0.0.2'), "IP B should still be allowed"
    print(f"\n  Isolation test: IP A denied, IP B allowed → PASS ✅")

    # Test 4: Violation counting
    tb3 = TokenBucket(rate=1, burst=1, violation_threshold=5)
    tb3.allow('10.0.0.3')  # Consume the 1 burst token
    for _ in range(10):
        tb3.allow('10.0.0.3')  # All denied
    violations = tb3.get_violations('10.0.0.3')
    print(f"\n  Violation count: {violations}")
    assert violations == 10, f"Expected 10 violations, got {violations}"
    assert tb3.is_pivot_attack('10.0.0.3'), "Should trigger pivot warning"
    assert not tb3.is_pivot_attack('10.0.0.3'), "Should not trigger twice"
    print(f"  → PASS ✅")

    # Test 5: Stats
    stats = tb3.get_stats()
    print(f"\n  Stats: {stats}")
    assert stats['active_buckets'] >= 1
    assert stats['total_violations'] >= 10
    print(f"  → PASS ✅")

    print(f"\n  All tests passed ✅")
    print("=" * 60)
