# Plan 1 — Full Automatic Data Collection + Merge (step by step)

*Collect a fresh full dataset (normal + all 6 attacks) in one command, auto-validated,
then merge it into `ML dataset/dataset_v2_master.csv` to create a bigger master. Uses the
new high-yield `run_full_collection_hy` so the flood classes are not row-thin.*

---

## Step 0 — (Recommended) Activate the integrated Snort 3 (Lua)

The "Snort 2.x detected" message means the controller VM has the **Snort 2.x binary**, so
`snort_monitor.py` auto-falls back to `snort.conf` + `alert_fast`. Collection still works
on 2.x (labels come from the rate counters + DAI + canonical-guarded Snort), so this step
is **optional for collecting** — but do it to get the clean 6-attack Snort 3 schema.

1. **Install the Snort 3 binary** on the controller VM (it is not in the repo). After
   install, confirm: `snort -V` must report **Version 3** (so `snort_monitor` stops
   detecting 2.x). If both versions exist, make the Snort 3 binary the one on `PATH`.
2. **Install the curated config + rules** (already in the repo):
   ```bash
   cd ~/.../GP/Controller
   sudo ./scripts/install_snort3_ips_config.sh        # copies sdn_ips.lua + sdn_ips_local.rules to /etc/snort
   sudo snort -c /etc/snort/sdn_ips.lua -T            # GATE: must validate clean
   ```
3. That's all — `snort_monitor.py` already points at `/etc/snort/sdn_ips.lua` and, when it
   sees Snort 3, launches with `-A alert_json`. **GATE:** on the next controller start the
   log should **not** say "Snort 2.x detected"; it starts Snort 3 on `ens33` + `snort_tap`.

*(If you can't install Snort 3 right now, skip Step 0 and collect on 2.x — proceed.)*

---

## Step 1 — Start the controller (VM1)

```bash
cd ~/.../GP/Controller
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
```
**GATE:** log shows `Feature schema mode: v2 (corrected)` and `ML engine loaded … pipeline`.
(ML stays OFF during collection — the harness sets it; detection only LABELS, never blocks.)

## Step 2 — Start the topology (VM2)

Redeploy the latest `topology.py` first (`git pull` on VM2), then:
```bash
cd "~/.../GP/SDN Topology"
sudo mn -c && sudo python3 topology.py
```
Register the two IoT devices as usual. **GATE:** `pingall` = 0% loss; the startup banner
shows the `run_full_collection_hy` hint (confirms the new file is loaded).
`which arpspoof || sudo apt-get install -y dsniff`.

## Step 3 — Collect everything with ONE command

```python
py net.run_full_collection_hy(net)          # ~2-2.5 h, walk away (or duration=120 for faster)
```
This automatically does, saving + auto-validating each on the controller:
1 normal session → ICMP → SYN → UDP → Port Scan → ARP → CPS, with the flood classes using
concurrent multi-target floods (~5× rows). **GATE:** it runs hands-off to the end.

## Step 4 — Check each session passed

Watch the VM1 log: each `CONTROL:ROTATE` prints `RESULT: PASS ✅`.
**GATE:** all 7 PASS. Re-collect any that come back ISSUES with the single-class command,
e.g. `py net.run_topup_session(net,'udp',rotate_as='dataset_session4_udp.csv')`.

## Step 5 — Merge into a bigger master

On VM1, merge the **existing master** with the 7 fresh sessions (hard 102-col guard):
```bash
python3 dataset_merge.py \
  "../ML dataset/dataset_v2_master.csv" \
  dataset_session1_normal.csv dataset_session2_icmp.csv dataset_session3_syn.csv \
  dataset_session4_udp.csv dataset_session5_portscan.csv dataset_session6_arpspoof.csv \
  dataset_session7_cps.csv \
  --output "../ML dataset/dataset_v3_master.csv"
```
(Adjust the relative path to wherever you run it.) This concatenates the old master +
the new sessions into a bigger `dataset_v3_master.csv` (+ `_training`).
**GATE:** merge succeeds; print the new per-class counts.

## Step 6 — Final validation

```bash
python3 validate_dataset.py "../ML dataset/dataset_v3_master.csv"
```
**GATE:** `RESULT: PASS ✅`; per-class counts higher than the old master; no newly-dead
features. The bigger master is now ready for retraining (RF, and later the autoencoder).

---

## At-a-glance order
0 (install Snort 3) → 1 controller up → 2 topology up → 3 `run_full_collection_hy` →
4 confirm 7× PASS → 5 merge old master + new sessions → 6 validate bigger master.
