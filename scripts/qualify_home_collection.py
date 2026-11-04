"""Generate sanitized PCAPs and compare extraction with independent golden values."""

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import threading
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, Dot1Q, ARP
from scapy.utils import wrpcap
from home_sensor import HomeCollection, collect


def hello(sni=True, ech=True):
    name = b"example.test"
    names = b"\0" + len(name).to_bytes(2, "big") + name
    body = len(names).to_bytes(2, "big") + names
    extensions = struct.pack("!HH", 0, len(body)) + body if sni else b""
    if ech:
        extensions += struct.pack("!HH", 65037, 0)
    data = b"\3\3" + bytes(32) + b"\0\0\2\x13\x01\1\0" + len(extensions).to_bytes(2, "big") + extensions
    handshake = b"\1" + len(data).to_bytes(3, "big") + data
    return b"\x16\3\1" + len(handshake).to_bytes(2, "big") + handshake


def fixtures():
    def frame(transport, stamp, incoming=False, ttl=64, ipv6=False):
        source, destination = ("198.51.100.20", "192.0.2.10") if incoming else ("192.0.2.10", "198.51.100.20")
        network = IPv6(src="2001:db8::10", dst="2001:db8:1::20", hlim=ttl) if ipv6 else IP(src=source, dst=destination, ttl=ttl)
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / Dot1Q(vlan=7) / network / transport
        packet.time = stamp
        return packet
    core = [frame(TCP(sport=12000, dport=22, flags="S", window=0), 0),
            frame(TCP(sport=12000, dport=80, flags=0, window=10), 1, ttl=62),
            frame(TCP(sport=12000, dport=80, flags="FPU", window=10)/b"ab", 2),
            frame(TCP(sport=12000, dport=80, flags="F", window=10), 3, ttl=62),
            frame(TCP(sport=80, dport=12000, flags="R"), 3.25, incoming=True),
            frame(ICMP(type=3, code=3), 3.5, incoming=True),
            frame(TCP(sport=12000, dport=443, flags="S", window=20), 5, ttl=61),
            frame(TCP(sport=12000, dport=443, flags="S", window=20), 6, ttl=63)]
    application = [frame(UDP(sport=12000,dport=53)/DNS(qd=DNSQR(qname="abcd.test", qtype=16)), 0),
        frame(UDP(sport=53,dport=12000)/DNS(qr=1, rcode=3, qd=DNSQR(qname="abcd.test", qtype=16)), .5, incoming=True),
        frame(TCP(dport=443,flags="PA")/hello(), 1),
        frame(TCP(dport=443,flags="PA")/hello(False, False), 2),
        frame(TCP(dport=80,flags="PA")/b"PATCH /%41?a='<> HTTP/1.1\r\nHost: example.test\r\n\r\n", 3)]
    fragment = Ether(src="02:00:00:00:00:01")/Dot1Q(vlan=7)/IP(src="192.0.2.10",dst="198.51.100.20",flags="MF",proto=17)/bytes(8)
    fragment.time = 0
    ipv6 = [frame(TCP(dport=443,flags="S", window=32), 0, ipv6=True)]
    def close(packets):
        trigger = Ether()/ARP(psrc="198.51.100.30", pdst="198.51.100.40")
        trigger.time = 10
        return packets + [trigger]
    return {"core": close(core), "application": close(application), "fragment": close([fragment]), "ipv6": close(ipv6)}


def qualify(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    expected_path = ROOT / "tests/fixtures/site-v3-golden.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    checks, failures = 0, []
    def compare(row, fields, label):
        nonlocal checks
        for name, value in fields.items():
            checks += 1
            raw = row.get(name)
            actual = float(raw) if raw else None
            if (actual != value if value is None else actual is None or not math.isclose(actual, value, rel_tol=1e-9, abs_tol=1e-9)):
                failures.append(dict(case=label, feature=name, expected=value, actual=actual))
    for case, packets in fixtures().items():
        path = directory / (case + ".pcap")
        wrpcap(str(path), packets)
        collector = HomeCollection(directory / case, ["192.0.2.0/24", "2001:db8::/64"],
                                   metadata=True, content=True, min_free_bytes=1, capture_source="pcap_replay")
        collect(SimpleNamespace(pcap=path), collector, threading.Event())
        collector.state = "replay_complete"
        collector.checkpoint(force=True)
        rows = []
        for output in collector.directory.glob("features-*.csv"):
            with output.open(newline="", encoding="utf-8") as source:
                rows.extend(csv.DictReader(source))
        target = expected[case] if case in expected else {"out_packets":1,"out_bytes":78,"g12_ttl_mean":64,"g11_syn_count":1}
        wanted = target if isinstance(target, list) else [target]
        if len(rows) != len(wanted):
            failures.append(dict(case=case, expected_rows=len(wanted), actual_rows=len(rows)))
        for row, fields in zip(rows, wanted):
            compare(row, fields, case)
        if case == "core" and set(wanted[0]) != set(collector.columns) - set(__import__("home_sensor").META_COLUMNS):
            failures.append(dict(case=case, error="Golden expectations do not cover every feature column"))
        if any(r["ground_truth"] != "UNKNOWN" or r["window_complete"] != "1" for r in rows):
            failures.append(dict(case=case, error="Incorrect label/window completeness"))
    result = {"version": "feature-qualification-v1", "status":"FAIL" if failures else "PASS", "checks":checks,
              "failures":failures, "golden_sha256":hashlib.sha256(expected_path.read_bytes()).hexdigest(),
              "scope":"Synthetic PCAP event-time checks of all feature columns and nonzero G11-G17 subsets; live mirroring/loss and attack accuracy untested."}
    (directory / "qualification.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.output_dir)
    print(json.dumps(result, indent=2))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
