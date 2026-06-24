#!/usr/bin/env python3
"""
Snort 3 Alert Reader - displays all Snort alerts and blocks trusted attack SIDs.
"""

import json
import time
import requests
import logging
import os
import sys
import subprocess
import ipaddress

DISPLAY_DEDUP_SECONDS = 10
BLOCK_DEDUP_SECONDS = 60
BLOCKED_RETRY_DEDUP_SECONDS = 10
INTERNAL_SDN_NETWORK = "10.0.0.0/8"
PROTECTED_IPS = {
    "127.0.0.1",
    "::1",
    "192.168.1.200",  # VM1/controller itself
    "192.168.1.201",  # VM2/Mininet VM; avoids breaking VXLAN/controller traffic
}

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [READER] %(levelname)s: %(message)s"
)
log = logging.getLogger(__name__)

SNORT_ALERT_FILE = "/var/log/snort/alert_json.txt"
BRIDGE_URL = "http://127.0.0.1:9000/block"

BLOCKING_SIDS = {
    1000001: "ICMP Flood",
    1000002: "TCP Port Scan",
    1000003: "SSH Brute Force",
    1000004: "UDP Flood",
    1000005: "Ryu REST API TCP Flood",
}

SUPPRESSED_DISPLAY_SIDS = {
    6,  # Decoder noise: (ipv4) IPv4 datagram length > captured length
}

last_displayed = {}
last_block_sent = {}
last_blocked_retry_displayed = {}


def parse_sid(rule):
    if not rule:
        return None
    try:
        parts = str(rule).split(":")
        if len(parts) >= 2:
            return int(parts[1])
        return int(rule)
    except ValueError:
        return None


def parse_addr_port(value):
    if not value:
        return "?", "?"
    value = str(value).strip()
    if value.startswith("["):
        end = value.rfind("]")
        ip = value[1:end] if end > 0 else "?"
        port = value[end + 2:] if end > 0 and len(value) > end + 2 else "?"
        return ip, port
    if ":" in value:
        ip, port = value.rsplit(":", 1)
        return ip or "?", port or "?"
    return value, "?"


def get_endpoint(alert, side):
    ap_value = alert.get(f"{side}_ap", "")
    if ap_value:
        return parse_addr_port(ap_value)

    ip = alert.get(f"{side}_addr") or alert.get(f"{side}_ip") or "?"
    port = alert.get(f"{side}_port") or "?"
    return str(ip), str(port)


def alert_name(alert, sid):
    return (
        alert.get("msg")
        or alert.get("message")
        or alert.get("alert_msg")
        or BLOCKING_SIDS.get(sid)
        or f"Snort Alert SID {sid}"
    )


def show_ids_alert(alert, sid, should_block):
    src_ip, src_port = get_endpoint(alert, "src")
    dst_ip, dst_port = get_endpoint(alert, "dst")
    proto = alert.get("proto", "?")
    alert_id = alert.get("pkt_num") or alert.get("event_id") or sid or "?"
    status = "BLOCKING" if should_block else "DISPLAY ONLY"
    line = "=" * 50

    if str(proto).upper() == "ICMP":
        from_text = src_ip
        to_text = dst_ip
    else:
        from_text = f"{src_ip}:{src_port}"
        to_text = f"{dst_ip}:{dst_port}"

    box = f"""
{line}
[!] IDS ALERT #{alert_id}  [{status}]
{line}
Attack : {alert_name(alert, sid)}
From   : {from_text}
To     : {to_text}
Proto  : {proto}
Rule   : SID {sid}
{line}
"""
    log.warning(box)


def show_blocked_retry_alert(alert, sid):
    src_ip, src_port = get_endpoint(alert, "src")
    dst_ip, dst_port = get_endpoint(alert, "dst")
    proto = alert.get("proto", "?")
    alert_id = alert.get("pkt_num") or alert.get("event_id") or sid or "?"
    line = "=" * 50

    if str(proto).upper() == "ICMP":
        from_text = src_ip
        to_text = dst_ip
    else:
        from_text = f"{src_ip}:{src_port}"
        to_text = f"{dst_ip}:{dst_port}"

    box = f"""
{line}
[!] IDS ALERT #{alert_id}  [ALREADY BLOCKED]
{line}
Attack : {alert_name(alert, sid)}
Status : Source IP is already blocked, but it is still trying to attack
From   : {from_text}
To     : {to_text}
Proto  : {proto}
Rule   : SID {sid}
{line}
"""
    log.warning(box)


def alert_key(alert, sid):
    src_ip, _ = get_endpoint(alert, "src")
    dst_ip, _ = get_endpoint(alert, "dst")
    proto = str(alert.get("proto", "?")).upper()
    return sid, src_ip, dst_ip, proto


def should_display_alert(alert, sid):
    key = alert_key(alert, sid)
    now = time.time()
    previous = last_displayed.get(key, 0)
    if now - previous < DISPLAY_DEDUP_SECONDS:
        return False
    last_displayed[key] = now
    return True


def should_send_block(src_ip, sid):
    key = sid, src_ip
    now = time.time()
    previous = last_block_sent.get(key, 0)
    if now - previous < BLOCK_DEDUP_SECONDS:
        return False
    last_block_sent[key] = now
    return True


def should_display_blocked_retry(alert, sid):
    key = alert_key(alert, sid)
    now = time.time()
    previous = last_blocked_retry_displayed.get(key, 0)
    if now - previous < BLOCKED_RETRY_DEDUP_SECONDS:
        return False
    last_blocked_retry_displayed[key] = now
    return True


def is_internal_sdn_ip(ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(INTERNAL_SDN_NETWORK)
    except ValueError:
        return False


def is_protected_ip(ip):
    return ip == "?" or ip in PROTECTED_IPS


def send_block(src_ip, sid):
    try:
        payload = {"src_ip": src_ip, "sid": sid}
        r = requests.post(BRIDGE_URL, json=payload, timeout=5)
        if r.status_code >= 400:
            log.error(f"Bridge error while blocking {src_ip}: {r.status_code} {r.text}")
    except Exception as e:
        log.error(f"Failed to reach bridge: {e}")


def block_external_ip(src_ip):
    if is_protected_ip(src_ip):
        return

    check_rule = [
        "iptables", "-C", "INPUT",
        "-s", src_ip,
        "-j", "DROP",
    ]
    add_rule = [
        "iptables", "-I", "INPUT",
        "-s", src_ip,
        "-j", "DROP",
    ]

    check = subprocess.run(
        check_rule,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if check.returncode == 0:
        return

    add = subprocess.run(
        add_rule,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if add.returncode == 0:
        log.warning(f"External attacker blocked with iptables: {src_ip}")
    else:
        log.error(f"Failed to add iptables DROP rule for external attacker: {src_ip}")


def is_external_ip_blocked(src_ip):
    if is_protected_ip(src_ip):
        return False

    check_rule = [
        "iptables", "-C", "INPUT",
        "-s", src_ip,
        "-j", "DROP",
    ]
    check = subprocess.run(
        check_rule,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return check.returncode == 0


def process_line(raw):
    raw = raw.strip()
    if not raw:
        return

    try:
        alert = json.loads(raw)
    except json.JSONDecodeError as e:
        log.error(f"JSON error ({e}): {raw[:80]}")
        return

    rule = alert.get("rule", "") or alert.get("sid", "")

    sid = parse_sid(rule)
    src_ip, _ = get_endpoint(alert, "src")
    should_block = sid in BLOCKING_SIDS and not is_protected_ip(src_ip)

    if sid in SUPPRESSED_DISPLAY_SIDS and not should_block:
        return

    if should_block and not is_internal_sdn_ip(src_ip) and is_external_ip_blocked(src_ip):
        if should_display_blocked_retry(alert, sid):
            show_blocked_retry_alert(alert, sid)
        return

    if should_display_alert(alert, sid):
        show_ids_alert(alert, sid, should_block)

    if should_block:
        if should_send_block(src_ip, sid):
            if is_internal_sdn_ip(src_ip):
                send_block(src_ip, sid)
            else:
                block_external_ip(src_ip)


def tail_file(filepath):
    while not os.path.exists(filepath):
        log.error(f"Waiting for file to appear: {filepath}")
        time.sleep(2)

    with open(filepath, "r") as f:
        f.seek(0, 2)

        while True:
            line = f.readline()
            if line:
                process_line(line)
            else:
                try:
                    if os.stat(filepath).st_ino != os.fstat(f.fileno()).st_ino:
                        break
                except Exception:
                    pass
                time.sleep(0.05)


if __name__ == "__main__":
    while True:
        try:
            tail_file(SNORT_ALERT_FILE)
        except PermissionError as e:
            log.error(f"Permission denied: {e}")
            log.error("Run with: sudo python3 snort_alert_reader.py")
            sys.exit(1)
        except Exception as e:
            log.error(f"Crash in tail loop: {e}")
            time.sleep(2)
