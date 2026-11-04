"""Bounded offline soak/restart exercise. It does not measure live capture capacity."""

import argparse
import csv
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Controller"))
from home_sensor import HomeCollection
from site_features import decode
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from collection_report import report


def exercise(directory, windows=1000, devices=4):
    if not 4 <= windows <= 10000 or not 1 <= devices <= 16:
        raise ValueError("Use 4..10000 windows and 1..16 devices")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    collection_dir = directory / "data"
    collector = HomeCollection(collection_dir, ["192.0.2.0/24"], min_free_bytes=1, capture_source="pcap_replay")
    run_ids = [collector.run_id]
    peak_rss = None
    try:
        import psutil
        process = psutil.Process()
    except ImportError:
        process = None
    for number in range(windows):
        if number == windows // 2:
            collector.state = "replay_complete"
            collector.checkpoint(force=True)
            collector = HomeCollection(collection_dir, ["192.0.2.0/24"], min_free_bytes=1, capture_source="pcap_replay")
            run_ids.append(collector.run_id)
        for device in range(devices):
            frame = Ether(src="02:00:00:00:00:01")/IP(src=f"192.0.2.{device+10}",dst="198.51.100.20")/TCP(flags="S",dport=443)
            packet = decode(Ether(bytes(frame)))
            packet["timestamp"] = number * 5
            collector.record(packet)
        collector.advance(number * 5 + 5)
        if process is not None and number % 100 == 0:
            peak_rss = max(peak_rss or 0, process.memory_info().rss)
    collector.state = "replay_complete"
    collector.checkpoint(force=True)
    checks, failures = 0, []
    for path in sorted(collection_dir.glob("features-*.csv")):
        with path.open(newline="", encoding="utf-8") as source:
            for row in csv.DictReader(source):
                checks += 1
                window = int(float(row["profile_windows_before"]))
                if row["ground_truth"] != "UNKNOWN" or float(row["out_pps"]) != .2 or float(row["device_new_dst_ratio"]) != (1.0 if window == 0 else 0.0):
                    failures.append("Count/rate/novelty/label invariant failed")
    quality = report(collection_dir)
    if checks != windows * devices or quality["integrity_issues"]:
        failures.append("Row totals or closed-run integrity failed")
    result = {"version":"runtime-qualification-v1", "status":"FAIL" if failures else "PASS", "failures":failures,
              "windows":windows,"devices":devices,"rows_checked":checks,"run_ids":run_ids,
              "elapsed_seconds":time.monotonic()-started,
              "artifact_bytes":sum(p.stat().st_size for p in collection_dir.iterdir() if p.is_file()),
              "sampled_peak_rss_bytes":peak_rss, "retained_profiles_at_end":len(collector.history.sources),
              "live_capacity":"NOT_MEASURED", "meaning":"Accelerated synthetic state/restart exercise; not a days-long Linux soak."}
    (directory / "runtime-qualification.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--windows", type=int, default=1000)
    parser.add_argument("--devices", type=int, default=4)
    args = parser.parse_args()
    result = exercise(args.output_dir, args.windows, args.devices)
    print(json.dumps(result, indent=2))
    return int(result["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
