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
import json
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
    # --- SYN Flood / DoS (Attack Type 1) ---
    'syn flood': 'SYN Flood',
    'synflood': 'SYN Flood',
    'dos': 'SYN Flood',
    'ddos': 'SYN Flood',
    'denial of service': 'SYN Flood',
    'flood': 'SYN Flood',
    'resource exhaustion': 'SYN Flood',

    # --- Port Scan (Attack Type 2) ---
    'port scan': 'Port Scan',
    'portscan': 'Port Scan',
    'portsweep': 'Port Scan',
    'nmap': 'Port Scan',
    'scan attempt': 'Port Scan',
    'reconnaissance': 'Port Scan',
    'fingerprint': 'Port Scan',

    # --- ICMP Flood (Attack Type 3) ---
    'icmp flood': 'ICMP Flood',
    'ping of death': 'ICMP Flood',
    'smurf': 'ICMP Flood',

    # --- ARP Spoofing (Attack Type 4) ---
    # 'arp cache overwrite' / 'arp mismatch' are the Snort 3 arp_spoof inspector
    # (GID 112) built-in messages; map them to the canonical class too.
    'arp cache overwrite': 'ARP Spoofing',
    'arp mismatch': 'ARP Spoofing',
    'arp spoof': 'ARP Spoofing',
    'arp poisoning': 'ARP Spoofing',
    'arp': 'ARP Spoofing',

    # --- UDP Flood (Attack Type 5) ---
    'udp flood': 'UDP Flood',
    'dns amplification': 'UDP Flood',

    # --- Control Plane Saturation (Attack Type 6) ---
    # CPS = hping3 --udp --flood -p ++1 (incrementing dst ports). Mapped from the
    # SID 1000006 rule message so it lands as a canonical class (see _compute_label).
    'control plane saturation': 'Control Plane Saturation',
    'control plane': 'Control Plane Saturation',

    # --- Other (still useful for Snort signature matching) ---
    'sql injection': 'SQL Injection',
    'sql inject': 'SQL Injection',
    'sqli': 'SQL Injection',
    'xss': 'XSS Attack',
    'cross-site scripting': 'XSS Attack',
    'exploit': 'Exploit Attempt',
    'buffer overflow': 'Exploit Attempt',
    'overflow': 'Exploit Attempt',
    'shellcode': 'Exploit Attempt',
    'malware': 'Malware',
    'trojan': 'Malware',
    'backdoor': 'Malware',
    'botnet': 'Malware',
    'brute force': 'Brute Force',
    'brute-force': 'Brute Force',
    'login attempt': 'Brute Force',
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


def _protocol_aware_reclassify(attack_type, proto, msg):
    """
    Post-classification fixup: Snort rules like SID 469 (ICMP PING NMAP)
    contain 'nmap' in the message causing classify_attack() to return
    'Port Scan'. But when the protocol is ICMP, that's wrong — it's an
    ICMP flood, not a port scan. Port scans use TCP/UDP by definition.
    """
    if not proto:
        return attack_type
    proto_upper = proto.upper()
    if proto_upper == 'ICMP':
        # ICMP cannot be a port scan (no ports). Reclassify.
        if attack_type in ('Port Scan', 'Exploit Attempt', 'Brute Force',
                          'SQL Injection', 'XSS Attack'):
            return 'ICMP Flood'
    return attack_type


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
# Alert JSON Parser (Snort 3 alert_json — the curated sdn_ips.lua schema)
# =============================================================================
# Each line is one JSON object. Fields emitted by Controller/snort3/sdn_ips.lua:
#   timestamp pkt_num proto src_ap dst_ap src_addr src_port dst_addr dst_port
#   rule sid msg priority action
# This parser returns the SAME dict shape as parse_alert_line() so every
# downstream consumer (_handle_snort_alert, traffic_capture._compute_label,
# the CSV snort_sid/active_snort_alerts columns) is unchanged.
# =============================================================================

def _json_endpoint(alert, side):
    """Resolve (ip, port) for 'src'/'dst' from addr/port or an 'addr:port' ap field."""
    ip = alert.get(f'{side}_addr') or alert.get(f'{side}_ip')
    port = alert.get(f'{side}_port')
    if not ip:
        ap = alert.get(f'{side}_ap')
        if ap:
            ap = str(ap).strip()
            if ap.startswith('['):              # IPv6 [addr]:port
                end = ap.rfind(']')
                ip = ap[1:end] if end > 0 else ap
                if end > 0 and len(ap) > end + 2 and not port:
                    port = ap[end + 2:]
            elif ':' in ap:                      # IPv4 addr:port
                left, _, right = ap.rpartition(':')
                ip = left or ap
                port = port or right
            else:
                ip = ap
    ip = str(ip) if ip not in (None, '') else '?'
    port = str(port) if port not in (None, '') else '?'
    return ip, port


def parse_alert_json_line(line):
    """Parse one Snort 3 alert_json line into the common alert dict (or None)."""
    if not line:
        return None
    line = line.strip()
    if not line.startswith('{'):
        return None
    try:
        j = json.loads(line)
    except (ValueError, TypeError):
        return None

    # SID/GID/REV: prefer explicit fields, else fill any MISSING piece from the
    # "gid:sid:rev" rule string. alert_json commonly emits `rule` + `sid` but NOT a
    # separate `gid` field, so we must parse `rule` even when `sid` is already set —
    # otherwise gid stays '?' (breaking (gid,sid) suppression + the CSV gid column).
    gid, sid, rev = j.get('gid'), j.get('sid'), j.get('rev')
    if j.get('rule'):
        parts = str(j.get('rule')).split(':')
        if len(parts) == 1:
            if sid in (None, ''):
                sid = parts[0]
        else:
            if gid in (None, ''):
                gid = parts[0]
            if sid in (None, ''):
                sid = parts[1]
            if len(parts) >= 3 and rev in (None, ''):
                rev = parts[2]

    src_ip, src_port = _json_endpoint(j, 'src')
    dst_ip, dst_port = _json_endpoint(j, 'dst')
    msg = j.get('msg') or j.get('message') or ''

    d = {
        'timestamp': str(j.get('timestamp') or ''),
        'gid': str(gid) if gid not in (None, '') else '?',
        'sid': str(sid) if sid not in (None, '') else '?',
        'rev': str(rev) if rev not in (None, '') else '?',
        'msg': msg,
        'classification': str(j.get('class') or j.get('classification') or ''),
        'priority': str(j.get('priority') or '?'),
        'proto': str(j.get('proto') or '?'),
        'src_ip': src_ip, 'src_port': src_port,
        'dst_ip': dst_ip, 'dst_port': dst_port,
        'raw': line,
    }
    d['attack_type'] = classify_attack(msg)
    return d


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

    def __init__(self, interface='ens33', interfaces=None, config_path='/etc/snort/sdn_ips.lua',
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
        # Alert output format the tailer should parse: 'json' (Snort 3 alert_json,
        # the curated sdn_ips.lua schema) or 'fast' (Snort 2.x alert_fast fallback).
        # Set authoritatively by start_snort() once the Snort version is known.
        self._alert_format = 'fast'
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
        # Hard blocklist: these SIDs are FULLY DROPPED (no storage, no callback, no CSV label).
        # They are known false positives in SDN/Mininet environments.
        # NOTE: SID 469 (ICMP PING NMAP) is intentionally NOT blocked here.
        # It fires during hping3 --icmp floods, and the protocol reclassifier
        # (_protocol_aware_reclassify) converts "Port Scan" → "ICMP Flood".
        # Alert dedup (30s window) prevents log flooding.
        # NOTE: with the curated Snort 3 ruleset (sdn_ips_local.rules, SIDs
        # 1000001-1000006), the noisy Snort 2.x community SIDs below no longer
        # fire at all — they are kept only so the 2.x fallback path stays quiet.
        # CRITICAL: 1000001 is the curated **ICMP Flood** rule, so it must NOT be
        # dropped here (it was a probe/test SID under the old community ruleset).
        self._blocked_sids = {
            6,               # Snort 3 decoder: IPv4 datagram length > captured length (mirror/offload noise)
            527,             # BAD-TRAFFIC same SRC/DST (TAP mirror artifact)
            366, 384, 408,   # ICMP PING, ICMP Echo Reply (normal pingall)
            399,             # ICMP Destination Unreachable Host Unreachable
            401,             # ICMP Destination Unreachable Network Unreachable
            402,             # ICMP Destination Unreachable Port Unreachable
            449,             # ICMP Time-To-Live Exceeded in Transit (traceroute)
            485,             # ICMP Dest Unreachable Comm Administratively Prohibited
            1917, 1923,      # SCAN UPnP/SSDP service discover (legitimate multicast)
            2657,            # SSLv2 Client_Hello (TLS negotiation, not an attack)
            11963,           # GPL ICMP info
            2100366,         # GPL PING
            2101390,         # GPL ICMP Echo Reply
            2101424,         # GPL DNS request
        }

        # Precise (GID, SID) suppression — surgical so we don't drop unrelated
        # builtins that happen to reuse a low SID (many GIDs have a SID 1 / SID 4).
        # These three are confirmed environment noise in this lab, not the 6
        # curated attacks (whose rules are SIDs 1000001-1000006):
        #   129:4   stream_tcp "TCP timestamp outside PAWS window" — mirror reorders
        #           normal iperf/http (br-snort + ens33 see duplicate/out-of-order segs)
        #   116:414 decoder "IPv4 packet to broadcast dest" — physical-LAN broadcast
        #           (e.g. 192.168.1.x discovery), nothing to do with the SDN data plane
        #   112:1   arp_spoof inspector — gratuitous/unsolicited ARP noise. Real ARP
        #           spoofing is still caught by DAI (Tier 2, independent of Snort), and
        #           a genuine cache-overwrite fires a different arp_spoof SID.
        self._blocked_gid_sids = {
            ('129', '4'),
            ('116', '414'),
            ('112', '1'),
        }

        # Alert deduplication: suppress repeated alerts per SOURCE DEVICE
        # to prevent log flooding during attacks. A single flood makes Snort
        # fire many DIFFERENT SIDs from the same host (BAD-TRAFFIC 524, MISC
        # 503/504, SNMP-misfire 1418/1420/1421 on victim responses, ...), so a
        # per-(sid, src_ip) key still produced ~40 boxes per attack. Keying on
        # src_ip alone caps the console to ~one alert per device per window
        # ("a single alert or two per device"). Storage + the CSV-labeling
        # callback are unaffected — they still receive every alert.
        self._dedup_window_seconds = 30
        self._dedup_cache = {}  # src_ip -> last_log_time

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
            if 'Version 3' in out or 'snort3' in out.lower():
                return 3
            if 'Version 2' in out or 'Snort 2' in out:
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
            self._log_warning("Snort 2.x detected. Note: This monitor is optimized for Snort 3 (Lua).")
            # Try standard Snort 2 config locations
            config_paths = [
                '/etc/snort/snort.conf',
                '/etc/snort/snort.lua'.replace('.lua', '.conf'),
                'snort.conf'
            ]
            config_path = next((p for p in config_paths if os.path.exists(p)), None)
            
            if not config_path:
                self._log_error(
                    "Snort 2.x config not found! Expected /etc/snort/snort.conf. "
                    "Run: sudo apt install snort-rules-default"
                )
                return False
            self._alert_filename = 'alert'
            self._alert_format = 'fast'
            # No -D for Snort 2 to catch startup errors
            snort_args = ['-A', 'fast', '-q']
        else:
            # Snort 3: drive the curated config (sdn_ips.lua) and consume its
            # structured alert_json output (the schema from sdn_ips_local.rules).
            config_path = self.config_path
            self._alert_filename = 'alert_json.txt'
            self._alert_format = 'json'
            # No -D for Snort 3 to catch startup errors
            snort_args = ['-A', 'alert_json', '-q']
            if snort_ver == 3:
                snort_args.append('--warn-all')

        if not os.path.exists(config_path):
            self._log_error(
                "Snort config not found at %s. Install the curated Snort 3 config "
                "first: sudo ./scripts/install_snort3_ips_config.sh", config_path
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
            
            # Use files for output to avoid blocking on PIPE buffers if Snort is noisy
            out_file = open(os.path.join(log_subdir, 'snort_stdout.log'), 'w')
            err_file = open(os.path.join(log_subdir, 'snort_stderr.log'), 'w')

            cmd = ['snort', '-c', config_path, '-i', iface, '-l', log_subdir] + snort_args
            self._log_info("Starting Snort IDS on interface %s (using %s)...", iface, config_path)
            try:
                # Use DEVNULL for stdin, and files for others
                proc = subprocess.Popen(
                    cmd, stdout=out_file, stderr=err_file, stdin=subprocess.DEVNULL,
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )
                time.sleep(2.0)
                if proc.poll() is not None:
                    # Snort failed immediately. Read the error from the file.
                    err_file.close() # Close to flush
                    with open(os.path.join(log_subdir, 'snort_stderr.log'), 'r') as f:
                        err = f.read()[:500]
                    self._log_error("Snort on %s failed: %s", iface, err or "(check log for details)")
                    continue
                
                self._snort_processes.append(proc)
                any_ok = True
                self._log_info("Snort on %s started (PID: %s)", iface, proc.pid)
            except FileNotFoundError:
                self._log_error("Snort binary not found! sudo apt install snort")
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
        """Parse an alert line, deduplicate, and invoke the callback."""
        if getattr(self, '_alert_format', 'fast') == 'json':
            alert = parse_alert_json_line(line)
        else:
            alert = parse_alert_line(line)
        if not alert:
            return

        sid = alert.get('sid', '?')
        gid = alert.get('gid', '?')
        try:
            sid_int = int(sid)
        except (ValueError, TypeError):
            sid_int = -1

        # Hard blocklist: fully drop known false-positive SIDs.
        # They never reach storage, callback, or the CSV labeler.
        if sid_int in self._blocked_sids:
            return
        # Precise (GID, SID) suppression for noise events that reuse a common SID.
        if (str(gid), str(sid)) in self._blocked_gid_sids:
            return

        # Protocol-aware reclassification: fix ICMP alerts being
        # labeled as "Port Scan" because the rule message contains "nmap".
        proto = alert.get('proto', '')
        alert['attack_type'] = _protocol_aware_reclassify(
            alert['attack_type'], proto, alert.get('msg', '')
        )

        src_ip = alert.get('src_ip', '?')
        now = time.time()

        with self._lock:
            self._alert_count += 1
            alert['alert_number'] = self._alert_count
            alert['detected_at'] = datetime.now().isoformat()
            self._alerts.append(alert)

        # --- Alert Deduplication / Rate Limiting ---
        # During floods, Snort fires per-packet (150K+ alerts/sec) across many
        # SIDs from the same host. Log the FIRST alert per SOURCE DEVICE, then
        # suppress all of that device's alerts for the dedup window.
        # The alert is ALWAYS stored and forwarded to the callback
        # (for CSV labeling), but the console log is suppressed.
        dedup_key = src_ip
        last_logged = self._dedup_cache.get(dedup_key, 0)
        should_log = (now - last_logged) >= self._dedup_window_seconds

        if should_log:
            self._dedup_cache[dedup_key] = now
            # Clean old entries from dedup cache periodically
            if len(self._dedup_cache) > 500:
                cutoff = now - self._dedup_window_seconds * 2
                self._dedup_cache = {
                    k: v for k, v in self._dedup_cache.items() if v > cutoff
                }

            self._log_warning(
                "\n"
                "========================================\n"
                "  \U0001f6a8 IDS ALERT #%d\n"
                "========================================\n"
                "  Attack : %s\n"
                "  From   : %s:%s\n"
                "  To     : %s:%s\n"
                "  Proto  : %s\n"
                "  Rule   : SID %s\n"
                "========================================",
                self._alert_count,
                alert['attack_type'],
                src_ip, alert['src_port'],
                alert['dst_ip'], alert['dst_port'],
                proto,
                alert['sid'],
            )

        # Always invoke callback (for CSV labeling) regardless of log suppression
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
