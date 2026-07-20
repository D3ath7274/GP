# Pre-Production Data-Collection & Learning Runbook (real network)

**Goal.** After Mode B is up and your real devices (phones, cameras, any-vendor IoT) + the Kali box
are connected, have the controller **gradually learn** — collecting a real-network dataset in the
**same 102-column v2 feature schema as the training data, but with real numbers** — then retrain so
the models fit *this* network before you ever enable blocking.

**Why this matters.** The shipped models were trained on the Mininet testbed (with its 2× mirror
double-count and synthetic devices). Real phone/camera/sensor traffic looks nothing like that, so
without this step the IPS will false-positive on your real devices. This runbook produces the
real-normal (and optionally real-attack) data that fixes it.

**Prereqs.** Mode B AP running (`t530_mode_b_ap_setup.md`); `Controller/ips_config.json` set for your
subnet (e.g. `"lan_cidr": "192.168.50.0/24"`); you can reach the controller on the t530.
Legend: **[t530]** controller host · **[dev]** a real device · **[kali]** attacker.

---

## Phase 1 — Launch in COLLECT mode & register every host
1. **[t530] Launch with the v2 schema (REQUIRED) — capture only, no blocking:**
   ```bash
   cd ~/GP/Controller
   sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=snort_tap IPS_V2_FEATURES=1 \
     python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
     Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee collect_run.log
   ```
   - **`IPS_V2_FEATURES=1` is mandatory** — the banner must read `Feature schema mode: v2 (corrected)`
     or the columns won't match the training schema.
   - Leave DETECT/ML **OFF** (the startup default = "capture only, all labels = normal"). This is the
     clean normal-collection mode: every 5-s window is written to `dataset.csv`, labeled normal, and
     nothing is blocked.
2. **[dev] Connect each device** to the AP SSID. Get its IP from the DHCP leases:
   ```bash
   [t530] cat /var/lib/misc/dnsmasq.leases        # MAC  IP  hostname
   ```
   > Tip: give important devices a **fixed IP** so registration sticks across reboots — add
   > `dhcp-host=<mac>,192.168.50.60` lines to `/etc/dnsmasq.d/ips-ap.conf`, then `systemctl restart dnsmasq`.
3. **[t530] Register / name every host** (so the dataset + dashboard label them meaningfully):
   ```bash
   python3 ipsctl.py REGISTER:NAME:phone-ali:192.168.50.51        # a phone / laptop
   python3 ipsctl.py REGISTER:NAME:workpc:192.168.50.52
   python3 ipsctl.py REGISTER:IOT:192.168.50.60:IOT:Camera        # an IoT device (type tag)
   python3 ipsctl.py REGISTER:NAME:frontcam:192.168.50.60         #   + a friendly name
   python3 ipsctl.py REGISTER:IOT:192.168.50.61:IOT:TempSensor
   python3 ipsctl.py REGISTER:NAME:tempsensor:192.168.50.61
   ```
   (Unregistered devices still get captured — auto-named `Host (ip)` — but tagging IoT enables the
   IoT device-baseline features.)
4. **[t530] Confirm the pipeline is live:**
   ```bash
   curl -s http://127.0.0.1:8081/ips/switches            # -> {"count": 1}
   wc -l dataset.csv ; sleep 8 ; wc -l dataset.csv        # -> GROWING as devices talk
   ```

## Phase 2 — Normal baseline collection (the gradual learning)
Let the network **live normally** — people browse, cameras stream, sensors report — with **no
attacks**. The controller writes a real-number row per flow per 5-s window continuously; that
accumulation *is* the learning.
- **Duration:** the longer the better. Minimum a few hours; **ideally 24 h+** to capture the daily
  cycle (idle night vs busy evening), and a **weekday + weekend** if you can. Sparse baselines =
  false positives later.
- **Let device baselines mature:** each device needs ~20 flows and ~180 s before its baseline
  features are trustworthy (`is_baseline_mature`). More time = better.
- **Snapshot as you go** (so a restart can't lose it):
  ```bash
  python3 ipsctl.py CONTROL:ROTATE:normal_day1.csv      # saves+rotates dataset.csv, starts fresh
  # or simply:  cp dataset.csv normal_$(date +%F_%H%M).csv
  ```
  > ⚠ The controller rotates `dataset.csv` → `.bak` **on every restart** — snapshot (or don't
  > restart) mid-collection. (`CONTROL:ROTATE` still saves the file; note its auto-validation step is
  > gone with the pruned tooling — the save itself works.)

## Phase 3 — Verify the collection is real & schema-correct
```bash
[t530] cd ~/GP/Controller
head -1 dataset.csv | tr ',' '\n' | wc -l          # ~102 columns = v2 schema OK
tail -n +2 dataset.csv | awk -F, '{print $NF}' | sort | uniq -c   # label column: should be all 'normal'/0
```
- **Real numbers check:** spot-check a few rows — packet rates, entropy, inter-arrival values should
  reflect *real* devices (bursty video from a camera, periodic small packets from a sensor), not the
  testbed's inflated counts. This is the "according to real numbers" confirmation.
- **Coverage check:** confirm every registered device appears as a source (grep its IP), so the
  baseline covers all of them.

## Phase 4 — (optional) Labeled attack samples, for the RF retrain
The **AE** only needs the normal data from Phase 2. To retrain the **Random Forest** on real
numbers, you also need real attack rows labeled by class. Collect them **without the block cutting
the sample short** using a forced label + no enforcement:
```bash
[t530] python3 ipsctl.py CONTROL:DETECT:OFF ; python3 ipsctl.py CONTROL:ML:OFF   # no labeling, no blocking
       python3 ipsctl.py "LABEL_OVERRIDE:192.168.50.99:SYN Flood"                # force-label the attacker's rows
[kali] sudo hping3 -S --flood -p 80 192.168.50.60          # run the attack ~30-60 s
[t530] python3 ipsctl.py CONTROL:ROTATE:attack_syn.csv     # snapshot this class
       python3 ipsctl.py "LABEL_OVERRIDE:192.168.50.99:clear"
```
Repeat per class (`ICMP Flood`, `UDP Flood`, `Port Scan`, `Control Plane Saturation`, `ARP
Spoofing`), snapshotting each. *(Alternative:* add the attacker's MAC to `protected_macs`, then
`DETECT:ON` auto-labels via Snort/rate while the block is refused — same effect, real tier labels.)*

## Phase 5 — Merge & retrain on the real data
Merge the snapshots (same header, so keep one):
```bash
[t530] cd ~/GP/Controller
head -1 normal_day1.csv > real_master.csv
for f in normal_*.csv attack_*.csv; do tail -n +2 "$f" >> real_master.csv; done
wc -l real_master.csv
```
**Recalibrate the AE to real normal (the main false-positive fix):**
```bash
python3 ml_models/build_ae_bundle.py \
  --csv real_master.csv \
  --h5  ml_models/autoencoder_tighter_bottleneck_16units.h5 \
  --percentile 99 \
  --out ml_models/ae_bundle.joblib
```
This re-fits the scaler + reconstruction-error threshold to **your** normal traffic (keeps the AE's
learned weights). That threshold is the dominant FP knob, so this alone fixes most false positives.
*(A full AE weight retrain needs the training notebook — restore it from `git checkout
pre-deployment-cleanup -- "Controller/ml_models/Grad_Autoencoder_4.ipynb"` — plus TensorFlow.)*

**Retrain the RF (only if you collected Phase 4 attacks) — on the training box with scikit-learn 1.6.1:**
```bash
python3 ml_models/retrain_rf_v4.py --csv real_master.csv --out ml_models/rf_pipeline_real.joblib
# review the report, then: mv ml_models/rf_pipeline_real.joblib ml_models/rf_pipeline.joblib
```
*(No attack data? Keep the shipped RF and rely on the recalibrated AE + Snort + rate — a valid
minimal path; the AE is what catches the unknown anyway.)*

## Phase 6 — Validate, then graduate to blocking
1. **Restart** the controller with the new models (banner shows the new AE threshold).
2. **[t530]** `CONTROL:DETECT:ON` + `CONTROL:ML:OBSERVE`. Let real normal traffic run again with **no
   attack** — **gate: 0 flags/blocks at rest**. If a device still trips the AE, raise its band
   (`CONTROL:ML:AE:BLOCK:0.85`) or add it to `protected_macs`, and re-check.
3. Run one controlled **[kali]** attack → confirm it's detected in the log.
4. **Graduate:** `CONTROL:ML:AUTHORIZE:0.85` (+ `IPS_EXTERNAL_BLOCK=1 IPS_MGMT_WHITELIST=<admin>` at
   launch). Keep critical devices in `protected_macs`. You're now enforcing on a model tuned to this
   network. Score it with `production_readiness_results.md`.

---

## Cheat-sheet
| Task | Command |
|---|---|
| Collect normal | launch + `DETECT:OFF` (default), let it run |
| Name a host | `ipsctl.py REGISTER:NAME:<name>:<ip>` |
| Tag IoT | `ipsctl.py REGISTER:IOT:<ip>:IOT:<type>` |
| Snapshot data | `ipsctl.py CONTROL:ROTATE:<file.csv>` or `cp dataset.csv <file>` |
| Label an attacker | `ipsctl.py "LABEL_OVERRIDE:<ip>:<Attack Type>"` … `:clear` |
| Recalibrate AE | `build_ae_bundle.py --csv real_master.csv --h5 …h5 --out …ae_bundle.joblib` |
| Retrain RF | `retrain_rf_v4.py --csv real_master.csv --out …` (sklearn 1.6.1) |
| Validate at rest | `DETECT:ON` + `ML:OBSERVE` → 0 flags |
| Go live | `ML:AUTHORIZE:0.85` |
