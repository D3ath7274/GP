"""
Snort 3 IDS Monitor for SDN Controller
=======================================
Manages the Snort 3 process lifecycle and parses alerts in real-time.
Designed to integrate with the Ryu SDN controller to report detected attacks.

Usage (standalone test):
    python3 snort_monitor.py

Usage (integrated with Ryu controller):
    from snort_monitor import SnortManager
    manager = SnortManager(interface='ens33', logger=self.logger, on_alert=callback)
    manager.start_snort()
    manager.start_monitoring()
"""

import subprocess
import threading
import time
import re
import os
import signal
from collections import deque
from datetime import datetime


# =============================================================================
# Attack Classification Map
# =============================================================================
# Maps keywords found in Snort rule messages to human-readable attack types.
# This is used to translate raw Snort alerts into clear reports like:
#   "SQL injection attack detected from 10.0.0.5"
# =============================================================================

ATTACK_CLASSIFICATIONS = {
    # SQL Injection
    'sql injection': 'SQL injection attack',
    'sql inject': 'SQL injection attack',
    'sql attack': 'SQL injection attack',
    'sqli': 'SQL injection attack',
    'sql select': 'SQL injection attack',
    'sql union': 'SQL injection attack',
    'sql blind': 'SQL injection attack',
    '1=1': 'SQL injection attack',
    'or 1=1': 'SQL injection attack',

    # Cross-Site Scripting (XSS)
    'xss': 'XSS (Cross-Site Scripting) attack',
    'cross-site scripting': 'XSS (Cross-Site Scripting) attack',
    'cross site scripting': 'XSS (Cross-Site Scripting) attack',
    'script injection': 'XSS (Cross-Site Scripting) attack',

    # SYN Flood / DoS
    'syn flood': 'SYN flood attack',
    'synflood': 'SYN flood attack',
    'dos': 'Denial of Service (DoS) attack',
    'ddos': 'Distributed Denial of Service (DDoS) attack',
    'denial of service': 'Denial of Service (DoS) attack',
    'flood': 'Flooding attack',
    'resource exhaustion': 'Resource exhaustion attack',

    # Port Scanning
    'port scan': 'Port scan',
    'portscan': 'Port scan',
    'nmap': 'Nmap scan',
    'scan attempt': 'Network scan attempt',
    'reconnaissance': 'Reconnaissance activity',
    'fingerprint': 'OS fingerprinting attempt',

    # Brute Force
    'brute force': 'Brute force attack',
    'brute-force': 'Brute force attack',
    'login attempt': 'Brute force login attempt',
    'failed login': 'Brute force login attempt',
    'password': 'Password attack',

    # Exploits
    'exploit': 'Exploit attempt',
    'buffer overflow': 'Buffer overflow exploit',
    'overflow': 'Buffer overflow exploit',
    'shellcode': 'Shellcode execution attempt',
    'code execution': 'Remote code execution attempt',
    'rce': 'Remote code execution attempt',
    'command injection': 'Command injection attack',
    'cmd injection': 'Command injection attack',

    # Malware / Trojan
    'malware': 'Malware detected',
    'trojan': 'Trojan activity detected',
    'backdoor': 'Backdoor activity detected',
    'ransomware': 'Ransomware activity detected',
    'worm': 'Worm activity detected',
    'botnet': 'Botnet activity detected',
    'c2': 'Command & Control (C2) communication',
    'c&c': 'Command & Control (C2) communication',
    'command and control': 'Command & Control (C2) communication',

    # Web Attacks
    'directory traversal': 'Directory traversal attack',
    'path traversal': 'Path traversal attack',
    'file inclusion': 'File inclusion attack',
    'lfi': 'Local file inclusion attack',
    'rfi': 'Remote file inclusion attack',
    'webshell': 'Web shell detected',
    'web shell': 'Web shell detected',
    'php injection': 'PHP injection attack',

    # Protocol Attacks
    'dns': 'DNS attack',
    'dns amplification': 'DNS amplification attack',
    'arp': 'ARP spoofing/poisoning',
    'arp spoof': 'ARP spoofing attack',
    'icmp': 'ICMP-based attack',
    'ping of death': 'Ping of Death attack',
    'smurf': 'Smurf attack',

    # Network Protocol Violations
    'bad traffic': 'Suspicious/malformed traffic',
    'suspicious': 'Suspicious activity',
    'anomaly': 'Traffic anomaly detected',
    'policy violation': 'Policy violation',
    'inappropriate': 'Inappropriate content/traffic',

    # SSH / Telnet
    'ssh': 'SSH attack',
    'telnet': 'Telnet attack',

    # SNMP
    'snmp': 'SNMP attack',
    'community string': 'SNMP community string exposure',

    # FTP
    'ftp': 'FTP attack',
    'ftp bounce': 'FTP bounce attack',
}


def classify_attack(msg):
    """
    Classify a Snort alert message into a human-readable attack type.
    Returns the most specific classification found, or the original message.
    """
    if not msg:
        return 'Unknown attack'

    msg_lower = msg.lower()

    # Try exact/specific matches first (longer keywords = more specific)
    best_match = None
    best_len = 0
    for keyword, attack_type in ATTACK_CLASSIFICATIONS.items():
        if keyword in msg_lower and len(keyword) > best_len:
            best_match = attack_type
            best_len = len(keyword)

    if best_match:
        return best_match

    # Fallback: return the original Snort message cleaned up
    return msg.strip('" ')


# =============================================================================
# Alert Fast Parser
# =============================================================================
# Snort 3 alert_fast format example:
# 08/18-14:15:20.123456 [**] [1:1000001:1] "ET SCAN Nmap ..." [**] [Classification: ...] [Priority: 2] {TCP} 10.0.0.1:12345 -> 192.168.1.101:80
# =============================================================================

# Regex for parsing Snort 3 alert_fast lines
ALERT_PATTERN = re.compile(
    r'(?P<timestamp>\d{2}/\d{2}-[\d:.]+)\s+'
    r'\[\*\*\]\s+'
    r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
    r'"?(?P<msg>[^"]*?)"?\s+'
    r'\[\*\*\]\s*'
    r'(?:\[Classification:\s*(?P<classification>[^\]]*)\]\s*)?'
    r'(?:\[Priority:\s*(?P<priority>\d+)\]\s*)?'
    r'\{(?P<proto>\w+)\}\s+'
    r'(?P<src_ip>[\d.]+)(?::(?P<src_port>\d+))?\s*->\s*'
    r'(?P<dst_ip>[\d.]+)(?::(?P<dst_port>\d+))?'
)

# Simpler fallback pattern for variations in alert format
ALERT_PATTERN_SIMPLE = re.compile(
    r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
    r'"?(?P<msg>[^"]*?)"?\s+'
    r'\[\*\*\]'
)

# Snort 2 fast format: {...} IP -> IP (IPs may appear without Classification/Priority)
ALERT_PATTERN_SNORT2 = re.compile(
    r'\{(?P<proto>\w+)\}\s+'
    r'(?P<src_ip>[\d.]+)(?::(?P<src_port>\d+))?\s*->\s*'
    r'(?P<dst_ip>[\d.]+)(?::(?P<dst_port>\d+))?'
)


def parse_alert_line(line):
    """
    Parse a single Snort alert_fast line into a structured dict.

    Returns dict with keys:
        timestamp, gid, sid, rev, msg, classification, priority,
        proto, src_ip, src_port, dst_ip, dst_port, attack_type, raw
    Or None if the line doesn't match.
    """
    if not line or '[**]' not in line:
        return None

    line = line.strip()
    match = ALERT_PATTERN.search(line)

    if match:
        d = match.groupdict()
        d['attack_type'] = classify_attack(d.get('msg', ''))
        d['src_port'] = d.get('src_port') or '?'
        d['dst_port'] = d.get('dst_port') or '?'
        d['priority'] = d.get('priority') or '?'
        d['classification'] = d.get('classification') or ''
        d['raw'] = line
        return d

    # Fallback: try simpler pattern
    simple = ALERT_PATTERN_SIMPLE.search(line)
    if simple:
        d = simple.groupdict()
        d['attack_type'] = classify_attack(d.get('msg', ''))
        d['timestamp'] = ''
        d['proto'] = '?'
        d['src_ip'] = '?'
        d['src_port'] = '?'
        d['dst_ip'] = '?'
        d['dst_port'] = '?'
        d['priority'] = '?'
        d['classification'] = ''
        d['raw'] = line

        # Try to extract IPs: Snort 2 fast has {PROTO} src -> dst
        snort2_match = ALERT_PATTERN_SNORT2.search(line)
        if snort2_match:
            g = snort2_match.groupdict()
            d['proto'] = g.get('proto', '?')
            d['src_ip'] = g.get('src_ip', '?')
            d['src_port'] = g.get('src_port') or '?'
            d['dst_ip'] = g.get('dst_ip', '?')
            d['dst_port'] = g.get('dst_port') or '?'
        else:
            ip_match = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?', line)
            if len(ip_match) >= 2:
                d['src_ip'] = ip_match[-2][0]
                d['src_port'] = ip_match[-2][1] or '?'
                d['dst_ip'] = ip_match[-1][0]
                d['dst_port'] = ip_match[-1][1] or '?'
            elif len(ip_match) == 1:
                d['src_ip'] = ip_match[0][0]

        return d

    return None


# =============================================================================
# SnortManager Class
# =============================================================================

class SnortManager:
    """
    Manages the Snort 3 IDS process and monitors alert output.

    Features:
    - Starts/stops Snort 3 as a subprocess
    - Tails the alert log file in a background thread
    - Parses alerts and classifies attack types
    - Invokes a callback for each new alert (for Ryu controller integration)
    - Maintains a ring buffer of recent alerts

    Parameters:
        interface (str): Network interface to monitor (default: 'ens33')
        config_path (str): Path to snort.lua config file
        log_dir (str): Directory for Snort logs
        logger: Logger instance (e.g., Ryu's self.logger). Falls back to print.
        on_alert (callable): Callback function invoked with alert dict for each new alert
        max_alerts (int): Max number of recent alerts to keep in memory
    """

    def __init__(self, interface='ens33', interfaces=None, config_path='/etc/snort/snort.lua',
                 log_dir='/var/log/snort', logger=None, on_alert=None,
                 max_alerts=1000):
        # Support single interface or multiple (for physical + TAP mirror)
        if interfaces is not None:
            self.interfaces = list(interfaces)
        else:
            self.interfaces = [interface]
        self.interface = self.interfaces[0]  # backward compat
        self.config_path = config_path
        self.log_dir = log_dir
        self.alert_file = os.path.join(log_dir, 'alert_fast.txt')
        self.logger = logger
        self.on_alert = on_alert
        self.max_alerts = max_alerts

        # State (lists for multi-interface)
        self._snort_processes = []
        self._monitor_threads = []
        self._running = False
        self._alerts = deque(maxlen=max_alerts)
        self._alert_count = 0
        self._lock = threading.Lock()
        # Rate-limit noisy rules (e.g. false positives from TAP/mirrored traffic)
        self._noisy_sids = {527}  # BAD-TRAFFIC same SRC/DST
        self._last_alert_per_sid = {}  # sid -> timestamp
        self._rate_limit_seconds = 120

    # ---- Logging helpers ----

    def _log_info(self, msg, *args):
        if self.logger:
            self.logger.info(msg, *args)
        else:
            print(f"[SNORT-INFO] {msg % args if args else msg}")

    def _log_warning(self, msg, *args):
        if self.logger:
            self.logger.warning(msg, *args)
        else:
            print(f"[SNORT-WARN] {msg % args if args else msg}")

    def _log_error(self, msg, *args):
        if self.logger:
            self.logger.error(msg, *args)
        else:
            print(f"[SNORT-ERROR] {msg % args if args else msg}")

    # ---- Snort Version Detection ----

    def _detect_snort_version(self):
        """Detect Snort 2 vs 3. Returns 2 or 3 or None."""
        try:
            result = subprocess.run(
                ['snort', '-V'], capture_output=True, text=True, timeout=5
            )
            out = (result.stdout or '') + (result.stderr or '')
            if 'Version 3' in out:
                return 3
            if 'Version 2' in out:
                return 2
        except Exception:
            pass
        return None

    def start_snort(self):
        """
        Start the Snort 3 process in IDS mode on the configured interface.
        Snort writes alerts to alert_fast.txt in the log directory.
        """
        running = [p for p in self._snort_processes if p and p.poll() is None]
        if running:
            self._log_warning("Snort already running on %d interface(s).", len(running))
            return True

        snort_ver = self._detect_snort_version()
        if snort_ver == 2:
            self._log_warning("Snort 2.x detected. For full features (Lua config), install Snort 3.")
            config_path = '/etc/snort/snort.conf'
            if not os.path.exists(config_path):
                config_path = self.config_path.replace('.lua', '.conf')
            self._alert_filename = 'alert'
            snort_args = ['-A', 'fast', '-q', '-D']
        else:
            config_path = self.config_path
            self._alert_filename = 'alert_fast.txt'
            snort_args = ['-A', 'alert_fast', '-q', '-D']
            if snort_ver == 3:
                snort_args.insert(-1, '--warn-all')  # Snort 3 only

        if not os.path.exists(config_path):
            self._log_error(
                "Snort config not found at %s. Run snort_setup.sh first!", config_path
            )
            return False

        self._snort_processes = []
        any_ok = False
        for iface in self.interfaces:
            log_subdir = os.path.join(self.log_dir, 'ids_' + iface.replace('/', '_'))
            os.makedirs(log_subdir, exist_ok=True)
            alert_path = os.path.join(log_subdir, self._alert_filename)
            if not os.path.exists(alert_path):
                open(alert_path, 'w').close()

            cmd = ['snort', '-c', config_path, '-i', iface, '-l', log_subdir] + snort_args
            self._log_info("Starting Snort IDS on interface %s...", iface)
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )
                time.sleep(1.5)
                if proc.poll() is not None:
                    err = proc.stderr.read().decode('utf-8', errors='ignore')[:500]
                    self._log_error("Snort on %s failed: %s", iface, err or "(no stderr)")
                    continue
                self._snort_processes.append(proc)
                any_ok = True
                self._log_info("Snort on %s started (PID: %s)", iface, proc.pid)
            except FileNotFoundError:
                self._log_error("Snort binary not found! sudo apt install snort")
                break
            except PermissionError:
                self._log_error("Permission denied. Run with sudo.")
                break
            except Exception as e:
                self._log_error("Snort on %s: %s", iface, str(e))

        return any_ok

    def stop_snort(self):
        """Gracefully stop all Snort processes."""
        self._running = False

        for proc in self._snort_processes:
            if proc and proc.poll() is None:
                self._log_info("Stopping Snort IDS (PID: %s)...", proc.pid)
                try:
                    if hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    else:
                        proc.terminate()
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                except (ProcessLookupError, OSError):
                    pass
        self._snort_processes = []

        for iface in self.interfaces:
            try:
                subprocess.run(
                    ['pkill', '-f', f'snort.*-i.*{re.escape(iface)}'],
                    timeout=5, capture_output=True
                )
            except Exception:
                pass

        for t in self._monitor_threads:
            if t and t.is_alive():
                t.join(timeout=5)
        self._monitor_threads = []
        self._log_info("Snort IDS monitor stopped. Total alerts processed: %d", self._alert_count)

    # ---- Alert Monitoring ----

    def start_monitoring(self):
        """
        Start background daemon threads that tail Snort alert files
        and process new alerts in real-time (one thread per interface).
        """
        if self._running:
            self._log_warning("Alert monitor is already running.")
            return

        self._running = True
        self._monitor_threads = []
        alert_fname = getattr(self, '_alert_filename', 'alert_fast.txt')
        for iface in self.interfaces:
            log_subdir = os.path.join(self.log_dir, 'ids_' + iface.replace('/', '_'))
            alert_path = os.path.join(log_subdir, alert_fname)
            t = threading.Thread(
                target=self._tail_alert_file,
                args=(alert_path,),
                name='SnortAlertMonitor-%s' % iface,
                daemon=True
            )
            t.start()
            self._monitor_threads.append(t)
        self._log_info(
            "Snort alert monitor started — watching %d interface(s): %s",
            len(self.interfaces), ', '.join(self.interfaces)
        )

    def _tail_alert_file(self, alert_file=None):
        """
        Tail the alert_fast.txt file, processing new lines as they appear.
        Similar to 'tail -f' behavior.
        """
        if alert_file is None:
            alert_file = self.alert_file
        while self._running:
            try:
                # Wait for file to exist
                while self._running and not os.path.exists(alert_file):
                    time.sleep(1)

                if not self._running:
                    break

                with open(alert_file, 'r') as f:
                    # Seek to end of file (only process new alerts)
                    f.seek(0, 2)

                    while self._running:
                        line = f.readline()
                        if line:
                            self._process_alert_line(line)
                        else:
                            # No new data, wait briefly
                            time.sleep(0.5)

                            # Check if file was rotated (size < current position)
                            try:
                                current_size = os.path.getsize(alert_file)
                                if current_size < f.tell():
                                    self._log_info("Alert file rotated, reopening...")
                                    break  # Break to reopen file
                            except OSError:
                                break

            except FileNotFoundError:
                time.sleep(2)
            except Exception as e:
                self._log_error("Alert monitor error: %s", str(e))
                time.sleep(5)

    def _process_alert_line(self, line):
        """Parse an alert line and invoke the callback."""
        alert = parse_alert_line(line)
        if not alert:
            return

        sid = alert.get('sid', '?')
        try:
            sid_int = int(sid)
        except (ValueError, TypeError):
            sid_int = -1

        with self._lock:
            self._alert_count += 1
            alert['alert_number'] = self._alert_count
            alert['detected_at'] = datetime.now().isoformat()
            self._alerts.append(alert)

        # Rate-limit noisy rules (false positives from TAP/mirrored traffic)
        now = time.time()
        if sid_int in self._noisy_sids:
            last = self._last_alert_per_sid.get(sid_int, 0)
            if now - last < self._rate_limit_seconds:
                return  # Skip log and callback for this repeat
            self._last_alert_per_sid[sid_int] = now

        # Log the alert
        self._log_warning(
            "\n"
            "========================================\n"
            "  🚨 IDS ALERT #%d\n"
            "========================================\n"
            "  Attack : %s\n"
            "  From   : %s:%s\n"
            "  To     : %s:%s\n"
            "  Proto  : %s\n"
            "  Rule   : [%s:%s:%s] %s\n"
            "  Priority: %s\n"
            "========================================",
            self._alert_count,
            alert['attack_type'],
            alert['src_ip'], alert['src_port'],
            alert['dst_ip'], alert['dst_port'],
            alert['proto'],
            alert.get('gid', '?'), alert['sid'], alert.get('rev', '?'),
            alert.get('msg', ''),
            alert.get('priority', '?')
        )

        # Invoke callback (for Ryu controller integration)
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as e:
                self._log_error("Alert callback error: %s", str(e))

    # ---- Query Methods ----

    def get_recent_alerts(self, count=50):
        """Return the last N alerts as a list of dicts."""
        with self._lock:
            return list(self._alerts)[-count:]

    def get_alert_count(self):
        """Return total number of alerts processed."""
        with self._lock:
            return self._alert_count

    def get_alerts_by_type(self):
        """Return a summary dict of alert counts grouped by attack type."""
        with self._lock:
            summary = {}
            for alert in self._alerts:
                atype = alert.get('attack_type', 'Unknown')
                summary[atype] = summary.get(atype, 0) + 1
            return summary

    def get_alerts_by_source(self):
        """Return a summary dict of alert counts grouped by source IP."""
        with self._lock:
            summary = {}
            for alert in self._alerts:
                src = alert.get('src_ip', '?')
                summary[src] = summary.get(src, 0) + 1
            return summary

    def is_snort_running(self):
        """Check if any Snort process is still alive."""
        if not self._snort_processes:
            return False
        return any(p and p.poll() is None for p in self._snort_processes)


# =============================================================================
# Standalone Test Mode
# =============================================================================

if __name__ == '__main__':
    import sys

    print("=" * 60)
    print("  Snort 3 IDS Monitor — Standalone Test")
    print("=" * 60)

    # Test the parser with sample alert lines
    test_lines = [
        '02/18-14:15:20.123456 [**] [1:1000001:1] "ET SCAN Nmap SYN Scan" [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.0.0.1:54321 -> 192.168.1.101:22',
        '02/18-14:16:30.654321 [**] [1:2000001:3] "ET WEB_SERVER SQL Injection Attempt" [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 10.0.0.5:44444 -> 192.168.1.101:80',
        '02/18-14:17:45.111111 [**] [1:3000001:1] "ET DOS SYN Flood Detected" [**] [Priority: 1] {TCP} 10.0.0.2:12345 -> 192.168.1.101:80',
        '02/18-14:18:00.222222 [**] [1:4000001:2] "ET MALWARE Backdoor Connection" [**] [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} 10.0.0.3:55555 -> 192.168.1.101:4444',
    ]

    print("\n--- Testing Alert Parser ---\n")
    for line in test_lines:
        alert = parse_alert_line(line)
        if alert:
            print(f"  ✅ {alert['attack_type']} from {alert['src_ip']}:{alert['src_port']}"
                  f" -> {alert['dst_ip']}:{alert['dst_port']} [{alert['proto']}]"
                  f" (SID: {alert['sid']})")
        else:
            print(f"  ❌ Failed to parse: {line[:60]}...")

    print("\n--- Testing Classification ---\n")
    test_msgs = [
        "SQL Injection attempt via SELECT",
        "SYN flood from external network",
        "Nmap port scan detected",
        "XSS script injection in HTTP",
        "Brute force SSH login attempt",
        "Unknown weird traffic pattern",
    ]
    for msg in test_msgs:
        classified = classify_attack(msg)
        print(f"  '{msg}' -> '{classified}'")

    # If run with 'monitor' argument, start actual monitoring
    if len(sys.argv) > 1 and sys.argv[1] == 'monitor':
        interface = sys.argv[2] if len(sys.argv) > 2 else 'ens33'
        print(f"\n--- Starting Live Monitoring on {interface} ---")
        print("Press Ctrl+C to stop.\n")

        def on_alert_callback(alert):
            print(f"  🚨 {alert['attack_type']} from {alert['src_ip']}")

        manager = SnortManager(
            interface=interface,
            on_alert=on_alert_callback
        )

        started = manager.start_snort()
        if started:
            manager.start_monitoring()
            try:
                while True:
                    time.sleep(10)
                    count = manager.get_alert_count()
                    if count > 0:
                        print(f"\n  [Status] Total alerts: {count}")
                        by_type = manager.get_alerts_by_type()
                        for atype, cnt in by_type.items():
                            print(f"    - {atype}: {cnt}")
            except KeyboardInterrupt:
                print("\nStopping...")
                manager.stop_snort()
        else:
            print("Failed to start Snort. Check permissions and configuration.")
    else:
        print(f"\nTo run live monitoring: python3 {sys.argv[0]} monitor [interface]")
