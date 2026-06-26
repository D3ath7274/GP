# Dataset Enlargement Runbook — hands-free recollection of richer datasets

*Re-collect the **same 7 datasets** (1 normal + the 6 attacks: ICMP / SYN / UDP floods,
Port Scan, ARP spoofing, Control Plane Saturation) with **far more rows per class**, then
merge into a bigger master to retrain the ML models (RF now, AE later).*

> **Run this on your ORIGINAL lab** (controller VM `192.168.1.200` + mininet VM
> `192.168.1.201`) — **not** the t530. That's the whole point: kick off the unattended
> collection here, then go test the t530 in parallel. The two are independent (different
> machines, different OpenFlow/UDP endpoints), so they don't interfere.

---

## Why this produces "richer rows" (the two levers)

Rows in a window = **concurrent flow keys × windows**, *not* packet volume. The old 1:1
attacks made thin flood classes. Two changes fix that — both already wired:

1. **Concurrent multi-target floods.** Each attacker hits **all other hosts at once**
   (`launch_attack_multi`), so one source = ~5 flow keys/window instead of 1 → ~5× rows.
2. **6 attack sources instead of 4.** The base topology only builds `sta1 sta2 h1 h2`.
   Registering the two IoT devices **`TempSensor` (10.0.0.5)** and **`Cam` (10.0.0.6)**
   adds 2 more flood sources → ~50% more attack rows again. *If you skip this, collection
   silently runs with 4 sources and you lose those rows.*

Rough yield with both levers, `duration=180`: **~1000+ attack rows per flood class** (6
sources × 5 targets × 36 windows), vs a few hundred before.

---

## Path A — Fully unattended (one command, recommended for hands-free)

A new opt-in hook (`AUTO_COLLECT=1`) auto-registers `TempSensor`+`Cam` and runs the whole
high-yield capture with **no CLI typing**. Start it, walk away, go work on the t530.

**A1. Controller VM (`.200`) — start it and leave it logging:**
```bash
cd ~/.../GP/Controller
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py 2>&1 | tee collect_run.log
```
- **GATE:** banner shows `Feature schema mode: v2 (corrected)` and `ML engine loaded … pipeline`.
- ML blocking is forced **OFF** by the collection harness (it only *labels*, never blocks) — nothing to toggle.

**A2. Mininet VM (`.201`) — `git pull` first (to get this `AUTO_COLLECT` hook), then:**
```bash
cd "~/.../GP/SDN Topology"
sudo mn -c && sudo AUTO_COLLECT=1 CONTROLLER_IP=192.168.1.200 python3 topology.py
```
That's it. The script registers the IoT sources, waits, then runs all 7 sessions
(normal → ICMP → SYN → UDP → Port Scan → ARP → CPS), **auto-saving + auto-validating each**.
- **GATE:** you see `AUTO_COLLECT: registering IoT sources …` then `AUTO_COLLECT: starting
  UNATTENDED full collection`. ~2–2.5 h. Leave both VMs running and **go to the t530**.
- Need `arpspoof`? `which arpspoof || sudo apt-get install -y dsniff` (once, before A2).

**Knobs (optional):** `AUTO_COLLECT_DURATION=120` (faster/fewer rows), `AUTO_COLLECT_NORMAL=600`
(normal-session seconds), `AUTO_COLLECT_MODE=topup` (only re-fill the thin classes, not all 7),
`AUTO_REGISTER_IOT=0` (skip IoT auto-registration). All default sensibly.

When it finishes it prints `AUTO_COLLECT: DONE …` and drops to the Mininet CLI. Skip to **Step 3**.

---

## Path B — Manual one command (if you'd rather drive the CLI)

Same result, you type two registrations + one collection command.

**B1–B2.** Start the controller (A1) and topology **without** `AUTO_COLLECT`:
```bash
cd "~/.../GP/SDN Topology" && sudo mn -c && sudo CONTROLLER_IP=192.168.1.200 python3 topology.py
```
**B3. In the Mininet CLI, register the two extra IoT sources, then collect:**
```python
py net.register_iot_device(net, 'TempSensor', '10.0.0.5/24', '00:00:00:00:00:05', 's1', 'IOT:TempSensor')
py net.register_iot_device(net, 'Cam', '10.0.0.6/24', '00:00:00:00:00:06', 's1', 'IOT:Camera')
py net.run_full_collection_hy(net)          # ~2–2.5 h, blocks the CLI — walk away
```
- **GATE:** `nodes` lists `TempSensor` and `Cam` before you launch the collection.

---

## Step 3 — Confirm every session passed (controller log)

On the controller VM, each `CONTROL:ROTATE` prints a validation result.
- **GATE:** all **7** sessions report `RESULT: PASS ✅`.
- **Re-collect any class that comes back `ISSUES`** (single command, ~20 min):
  ```python
  py net.run_topup_session(net, 'udp', rotate_as='dataset_session4_udp.csv')
  ```
  (kinds: `icmp syn udp scan arp cps`). It overwrites that one session file in place.

The 7 files land in the controller's working dir:
`dataset_session1_normal.csv … dataset_session7_cps.csv`.

---

## Step 4 — Merge into a bigger master (richer = old master + new sessions)

On the controller VM (`Controller/`), merge the **existing master** with the 7 fresh
sessions. `dataset_merge.py` enforces the hard 102-column schema guard and writes both the
audit master and the meta-stripped training file:
```bash
python3 dataset_merge.py \
  "../ML dataset/dataset_v2_master.csv" \
  dataset_session1_normal.csv dataset_session2_icmp.csv dataset_session3_syn.csv \
  dataset_session4_udp.csv dataset_session5_portscan.csv dataset_session6_arpspoof.csv \
  dataset_session7_cps.csv \
  --output "../ML dataset/dataset_v3_master.csv"
```
- **GATE:** prints `Schema matches traffic_capture.py ALL_COLUMNS (102 columns)`, per-file row
  counts, the per-class distribution, and `Data quality: ✅ PASS`. It also emits
  `dataset_v3_master_training.csv` (meta columns stripped — the file you retrain on).
- *To enlarge the SAME class set without keeping old rows, just omit the
  `dataset_v2_master.csv` argument and merge only the 7 new files.*

---

## Step 5 — Final validation of the enlarged master

```bash
python3 validate_dataset.py "../ML dataset/dataset_v3_master.csv"
```
- **GATE:** `RESULT: PASS ✅`; per-class counts visibly higher than the old master; no class
  flagged `CRITICALLY LOW`; no newly-dead (all-zero/constant) features.

The enlarged `dataset_v3_master_training.csv` is now ready to retrain the RF (and re-fit /
re-export the AE bundle) — that retraining is a separate step done off the VMs.

---

## At-a-glance order
**A:** controller up → `sudo AUTO_COLLECT=1 … python3 topology.py` → walk to the t530.
**Then:** 3 confirm 7× PASS → 4 merge old master + new sessions → 5 validate enlarged master.

## Notes & gotchas
- **Don't run this collection *on* the t530 while you're stress-testing it** — recollect on
  the lab VMs so the 8 GB t530 isn't doing both. Keeping them separate is the point.
- **Disk:** 7 sessions + a v3 master are tens of MB; trivial. **RAM** on the mininet VM is
  the constraint during floods — `_bump_conntrack` already raises `nf_conntrack_max` so flood
  packets aren't silently dropped (was the old "table full" bug).
- **Fewer rows than expected?** Almost always means `TempSensor`/`Cam` weren't registered
  (4 sources, not 6) — check `nodes`, or that an attack class came back `ISSUES` (re-run it via Step 3).
- **CPS/Port Scan/ARP** are naturally lower-volume than the floods; ARP is auto-run longer
  (300 s). That's expected — they only need to clear the per-class floor, not match the floods.
- Sibling doc `data_collection_plan.md` is the original (manual) version of this; this runbook
  supersedes it for hands-free enlargement. Snort 3 is **not required** to collect (labels come
  from rate counters + DAI + Snort); see `data_collection_plan.md` Step 0 if you want it on.
```
