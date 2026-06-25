# Full Project Test Guide — Snort, RF, and AutoEncoder

Step-by-step procedure to test **each detection pipeline separately** and see
verifiable results in the controller log. Based on `context_claude.md` and the
current codebase (`Controller.py`, `traffic_capture.py`, `topology.py`).

**Testbed (two VMs on one LAN):**

| VM | Role | IP | What runs |
|---|---|---|---|
| VM1 | Controller | `192.168.1.19` | Ryu, Snort 3, ML engines, traffic capture |
| VM2 | Topology | `192.168.1.26` | Mininet-WiFi (`topology.py`) |

**Mininet hosts:** `sta1` 10.0.0.1, `sta2` 10.0.0.2, `h1` 10.0.0.3, `h2` 10.0.0.4 (server),
`TempSensor` 10.0.0.5, `Cam` 10.0.0.6.

**Four tiers (block if ANY fires in AUTHORIZE mode):**

| Tier | Pipeline | What you test |
|---|---|---|
| 1 | Snort signatures | Signature-based IDS + instant block |
| 2 | Rate counters + DAI | (bundled with DETECT ON; not isolated here) |
| 3 | Random Forest | Closed-world attack classification |
| 4 | Autoencoder | Open-world anomaly / zero-day net |

---

## Part 0 — One-time setup (do once per VM refresh)

### 0.1 Sync code to both VMs

From your dev machine:

```bash
# On VM1 (controller) and VM2 (topology), pull or scp the GP repo.
cd /path/to/GP
git pull   # or scp the Controller/ and SDN\ Topology/ folders
```

**GATE:** `Controller/Controller.py`, `Controller/ml_models/rf_pipeline.joblib`, and
`Controller/ml_models/ae_bundle.joblib` all exist on VM1.

### 0.2 Confirm topology points at the controller

On VM2, open `SDN Topology/topology.py` and verify:

```python
CONTROLLER_IP = '192.168.1.19'   # must match VM1
```

### 0.3 Install Snort 3 config (VM1, once)

```bash
cd /path/to/GP/Controller
sudo ./scripts/install_snort3_ips_config.sh
sudo snort -c /etc/snort/sdn_ips.lua -T
```

**GATE:** `snort -V` reports v3.x and config test passes.

If Snort 3 is not installed, the controller falls back to Snort 2.x (`snort.conf` +
`alert_fast`). Signature testing still works but is noisier (community rules). Install
Snort 3 for the clean 6-attack schema (SIDs 1000001–1000004 + inspectors).

### 0.4 Install RF runtime deps in Ryu's Python (VM1)

```bash
# Use the SAME interpreter ryu-manager uses — do NOT repoint system python.
pip install --only-binary=:all: scikit-learn==1.6.1 "pandas<2.3" "numpy<2.3" joblib
python3 -c "import sklearn; print(sklearn.__version__)"   # expect 1.6.1
```

AE needs **only NumPy** (already present). No TensorFlow.

### 0.5 (Optional) RF train/serve sanity check

```bash
cd /path/to/GP/Controller
python3 verify_inference.py --model-dir ml_models \
    --data dataset_v2_master_training.csv --ref rf_reference_predictions.csv
```

**GATE:** `RESULT: PASS ✅`

### 0.6 Raise conntrack limit on topology VM (before floods)

From the Mininet CLI after topology starts:

```python
py net._bump_conntrack()
```

Prevents `nf_conntrack: table full, dropping packet` during floods.

---

## Part 1 — Start the system (every test session)

You need **two terminals**.

### Terminal A — VM1 (Controller)

```bash
cd /path/to/GP/Controller
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
# Or, if using the unified file:
# sudo IPS_V2_FEATURES=1 ryu-manager Controller_main.py
```

**GATE — wait for all of these in the log:**

```
Feature schema mode: v2 (corrected)
ML engine loaded end-to-end pipeline … (7 classes)
AE engine loaded …/ae_bundle.joblib (60 features, threshold=0.03750, 4 layers)
Snort IDS started …          # or monitoring started
UDP command listener started on port 9999
```

Leave this terminal open and watch it during every test.

### Terminal B — VM2 (Topology)

```bash
cd "/path/to/GP/SDN Topology"
sudo python3 topology.py
```

At the `mininet-wifi>` prompt:

```python
py net.pingall()                    # confirm connectivity
py net._bump_conntrack()            # flood safety
py net.start_background_traffic(net)  # optional but helps baselines mature
```

**GATE:** `pingall` succeeds; controller shows `port added` / packet activity.

### Sending control commands

From VM2 Mininet CLI (topology helpers):

```python
py net.detect_on(net)      # CONTROL:DETECT:ON
py net.detect_off(net)     # CONTROL:DETECT:OFF
```

From VM1 or VM2 shell (direct UDP):

```bash
echo -n "CONTROL:ML:OBSERVE" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:AUTHORIZE:0.90" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:OFF" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:UNBLOCK:10.0.0.1" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:STATS" | nc -u -w1 192.168.1.19 9999
```

---

## Part 2 — Test Snort (Tier 1, signature-based)

**Goal:** Prove Snort sees mirrored traffic, fires the correct SID/class, labels flows,
and can block in AUTHORIZE mode.

### 2.1 Configure for Snort-only view

Snort runs inside the controller regardless of DETECT mode, but **labeling and blocking**
from signatures need DETECT ON. Turn ML off so RF/AE do not confuse the log.

**VM2 or UDP:**

```python
py net.detect_on(net)
```

```bash
echo -n "CONTROL:ML:OFF" | nc -u -w1 192.168.1.19 9999
```

**GATE (VM1 log):** `DETECTION MODE: ON` and `ML MODE: OFF`.

### 2.2 Enable Snort instant blocking (optional but recommended for block test)

```bash
echo -n "CONTROL:ML:AUTHORIZE:0.90" | nc -u -w1 192.168.1.19 9999
```

In AUTHORIZE mode, canonical Snort alerts trigger **instant** `block_attacker()` via
`_handle_snort_alert` (separate from RF/AE thresholds). You should see:

```
[SNORT] BLOCKED 10.0.0.1 (ICMP Flood) — instant signature match
```

plus the formatted `ATTACKER BLOCKED` box with OpenFlow DROP details.

### 2.3 Run one attack at a time

From Mininet CLI — pick **one** attack per test so logs stay readable:

```python
py net.run_attack_session(net, 'icmp')   # ~8 pairs, long — use duration=30 for a quick test:
# Quick single shot:
py net.launch_attack(net, 'sta1', 'icmp', target='10.0.0.4', duration=30, settle=10)
```

| Attack | Command | Expected Snort signal |
|---|---|---|
| ICMP Flood | `launch_attack(..., 'icmp')` | SID **1000001**, msg "ICMP Flood" |
| SYN Flood | `launch_attack(..., 'syn')` | SID **1000002**, msg "SYN Flood" |
| UDP Flood | `launch_attack(..., 'udp')` | SID **1000003**, msg "UDP Flood" |
| Port Scan | `launch_attack(..., 'scan')` | GID **122** (port_scan inspector) |
| ARP Spoof | `launch_attack(..., 'arp')` | GID **112** (arp_spoof) or DAI box |
| CPS | `launch_attack(..., 'cps')` | SID **1000004**, msg "Control Plane Saturation" |

### 2.4 What to look for (VM1 controller log)

**A. Snort alert (rate-limited, from `snort_monitor.py`):**

```
[SID 1000001] ICMP Flood from 10.0.0.1 → 10.0.0.4
```

**B. Dataset labeling (every 5 s window in `dataset.csv` / flush log):**

- `label` = `attack`
- `attack_type` = canonical class (e.g. `ICMP Flood`)
- `snort_sid` populated, `active_snort_alerts` > 0

**C. Blocking (if AUTHORIZE + canonical alert):**

```
╔══════════════════════════════════════════════════════════╗
║  🚫 ATTACKER BLOCKED                                     ║
║  Attack    : ICMP Flood                                  ║
║  Detection : snort-1000001                               ║
╚══════════════════════════════════════════════════════════╝
```

**D. Verify Snort log file directly (VM1, another shell):**

```bash
sudo tail -f /var/log/snort/alert_json.txt
# Snort 2.x fallback:
# sudo tail -f /var/log/snort/alert_fast.txt
```

### 2.5 Snort test checklist

| Attack | Snort alert? | Correct class? | Block (if AUTHORIZE)? | PASS? |
|---|---|---|---|---|
| ICMP | SID 1000001 | ICMP Flood | DROP on attacker MAC | |
| SYN | SID 1000002 | SYN Flood | | |
| UDP | SID 1000003 | UDP Flood | | |
| Scan | port_scan GID 122 | Port Scan | | |
| ARP | arp_spoof / DAI | ARP Spoofing | | |
| CPS | SID 1000004 | Control Plane Saturation | | |

**Release a blocked host:**

```bash
echo -n "CONTROL:UNBLOCK:10.0.0.1" | nc -u -w1 192.168.1.19 9999
```

### 2.6 Snort troubleshooting

| Symptom | Fix |
|---|---|
| No Snort alerts during flood | Confirm TAP: `ip link show snort_tap`; confirm mirror started in controller log |
| Only decoder SID 6 (truncated IPv4) | `sudo ./scripts/disable_capture_offloads.sh snort_tap ens33` |
| Wrong/noisy SIDs (469, etc.) | Install Snort 3 + `install_snort3_ips_config.sh`; confirm `config_path=/etc/snort/sdn_ips.lua` |
| Alerts but no block | Need `CONTROL:ML:AUTHORIZE`; attack must be in `CANONICAL_ATTACKS`; MAC must be known |

---

## Part 3 — Test Random Forest (Tier 3, anomaly classification)

**Goal:** See the RF classify attacks **on its own**, with confidence scores, without
Snort/rate tiers pre-labeling flows ("shadowing").

### 3.1 Configure pure-ML test mode

```python
py net.detect_off(net)
```

```bash
echo -n "CONTROL:ML:OBSERVE" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:FLAG:0.80" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:BLOCK:0.90" | nc -u -w1 192.168.1.19 9999
```

**Why DETECT OFF:** With DETECT ON, rate counters / Snort label floods first
(`label != 0`), and the RF hook **skips** those rows. DETECT OFF keeps every flow at
`label == 0` so RF scores **all** of them.

**GATE (VM1):** `ML MODE: OBSERVE`.

### 3.2 Run attacks

Quick per-type test:

```python
py net.launch_attack(net, 'sta1', 'syn', duration=60, settle=15)
py net.launch_attack(net, 'sta1', 'icmp', duration=60, settle=15)
py net.launch_attack(net, 'h1', 'udp', duration=60, settle=15)
py net.launch_attack(net, 'sta2', 'scan', duration=25, settle=15)
py net.launch_attack(net, 'Cam', 'arp', duration=25, settle=15)
py net.launch_attack(net, 'sta1', 'cps', duration=60, settle=15)
```

Or all six in one command (long):

```python
py net.run_full_collection_hy(net)
```

### 3.3 What to look for (VM1 log)

Every scored 5-second window prints:

```
[ML-OBSERVE] 10.0.0.1 → 10.0.0.4  verdict=SYN Flood  conf=0.87  band=BLOCK
```

| Field | Meaning |
|---|---|
| `verdict` | RF predicted class (one of 7: normal + 6 attacks) |
| `conf` | `max(predict_proba)` — model confidence |
| `band` | `SILENT` (<0.80 flag), `FLAG` (0.80–0.90), `BLOCK` (≥0.90) |

**Expected behaviour:**

- **During real attacks:** `verdict` matches attack type; `conf` often ≥ 0.80 on strong floods.
- **During normal/background:** `verdict=normal` or low confidence; minimal log spam.
- Thin classes (SYN/ICMP/UDP) may sit in FLAG band (0.80–0.90) — note for retrain.

### 3.4 RF stats

```bash
echo -n "CONTROL:ML:STATS" | nc -u -w1 192.168.1.19 9999
```

Look for: `total_predictions`, `total_attacks_detected`, `avg_inference_ms`.

### 3.5 RF blocking test (optional)

```bash
echo -n "CONTROL:ML:AUTHORIZE:0.90" | nc -u -w1 192.168.1.19 9999
```

Re-run one attack. **GATE:** only windows with `conf ≥ 0.90` install DROP rules;
sub-threshold traffic is not blocked.

```bash
echo -n "CONTROL:UNBLOCK:10.0.0.1" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:OBSERVE" | nc -u -w1 192.168.1.19 9999
```

### 3.6 RF results table (fill in during test)

| Attack launched | RF verdict | Typical conf | Band (FLAG/BLOCK) | PASS? |
|---|---|---|---|---|
| ICMP Flood | ICMP Flood | | | |
| SYN Flood | SYN Flood | | | |
| UDP Flood | UDP Flood | | | |
| Port Scan | Port Scan | | | |
| ARP Spoof | ARP Spoofing | | | |
| CPS | Control Plane Saturation | | | |
| Normal only | normal | < 0.80 | SILENT | |

---

## Part 4 — Test AutoEncoder (Tier 4, anomaly detection)

**Goal:** See the AE flag anomalies **independently** of the RF's closed-world labels.
RF and AE run **concurrently** on the same window row; look for `[AE-OBSERVE]` lines.

### 4.1 Same mode as RF (DETECT OFF + OBSERVE)

Keep the settings from Part 3:

```python
py net.detect_off(net)
```

```bash
echo -n "CONTROL:ML:OBSERVE" | nc -u -w1 192.168.1.19 9999
```

AE bands (fixed in `Controller.py`, no live UDP command yet):

| AE confidence | Action in OBSERVE | Action in AUTHORIZE |
|---|---|---|
| < 0.60 | **Silent** (no log) | No action |
| 0.60 – 0.73 | Log `[AE-OBSERVE]` band=FLAG | Flag + evidence |
| ≥ 0.73 | Log band=BLOCK | OpenFlow DROP, label `Anomaly (AE)` |

### 4.2 Run attacks (same commands as Part 3)

```python
py net.launch_attack(net, 'sta1', 'syn', duration=60, settle=15)
# … repeat per attack type
```

### 4.3 What to look for (VM1 log)

AE only logs when `conf ≥ 0.60` (keeps normal traffic quiet):

```
[AE-OBSERVE] 10.0.0.1 → 10.0.0.4  anomaly conf=0.81  err=0.1620  band=BLOCK
```

| Field | Meaning |
|---|---|
| `conf` | `error / (error + threshold)` — 0.5 at threshold (0.0375) |
| `err` | MSE reconstruction error |
| `band` | FLAG (0.60–0.73) or BLOCK (≥0.73) |

**Expected from validation (lab dataset):**

- Normal traffic: mean conf ≈ **0.16** (mostly silent, below 0.60)
- Attack traffic: mean conf ≈ **0.73**; ~47% of attack windows ≥ 0.73

### 4.4 AE vs RF side-by-side

During one SYN flood you should see **both** lines for the same flow window:

```
[ML-OBSERVE] 10.0.0.1 → 10.0.0.4  verdict=SYN Flood  conf=0.87  band=BLOCK
[AE-OBSERVE] 10.0.0.1 → 10.0.0.4  anomaly conf=0.81  err=0.1620  band=BLOCK
```

RF names the attack type; AE says "anomaly" without needing to have seen that class
during AE training (trained on **normal rows only**).

### 4.5 AE blocking test (optional)

```bash
echo -n "CONTROL:ML:AUTHORIZE:0.90" | nc -u -w1 192.168.1.19 9999
```

AE blocks at **≥ 0.73** (lower bar than RF's 0.90 — it is the zero-day net).
Look for `Anomaly (AE)` in the block log.

### 4.6 AE results table

| Attack launched | AE logged? (conf≥0.60) | Typical conf | band BLOCK (≥0.73)? | PASS? |
|---|---|---|---|---|
| ICMP Flood | | | | |
| SYN Flood | | | | |
| UDP Flood | | | | |
| Port Scan | | | | |
| ARP Spoof | | | | |
| CPS | | | | |
| Normal only | No (silent) | < 0.60 | No | |

---

## Part 5 — Full stacked test (as-deployed behaviour)

**Goal:** All tiers active together — how the system behaves in production.

```python
py net.detect_on(net)
```

```bash
echo -n "CONTROL:ML:AUTHORIZE:0.90" | nc -u -w1 192.168.1.19 9999
```

Run one attack:

```python
py net.launch_attack(net, 'sta1', 'icmp', duration=60, settle=15)
```

**Expected cascade (fastest tier wins first):**

1. **Snort** fires within seconds → instant block if canonical (Tier 1).
2. **Rate counters** confirm flood → block if Snort missed it (Tier 2).
3. **RF** scores only `label==0` survivors → block at conf ≥ 0.90 (Tier 3).
4. **AE** scores same survivors → block at conf ≥ 0.73 (Tier 4).

Most-severe action wins: `block > flag > silent`.

**Rollback to safe mode anytime:**

```bash
echo -n "CONTROL:ML:OFF" | nc -u -w1 192.168.1.19 9999
```

```python
py net.detect_off(net)
```

---

## Part 6 — Quick reference: mode matrix

| What you want to test | DETECT | ML mode | Attack command |
|---|---|---|---|
| Snort signatures only | ON | OFF | `launch_attack(..., 'icmp')` |
| Snort + instant block | ON | AUTHORIZE | same |
| RF confidence only | OFF | OBSERVE | `launch_attack` or `run_full_collection_hy` |
| AE anomaly only | OFF | OBSERVE | same (read `[AE-OBSERVE]` lines) |
| RF + AE together | OFF | OBSERVE | same (both log lines per window) |
| RF blocking | OFF | AUTHORIZE (block 0.90) | one attack |
| AE blocking | OFF | AUTHORIZE | one attack (blocks at 0.73) |
| Full production stack | ON | AUTHORIZE | one attack |

---

## Part 7 — End-to-end session script (copy/paste order)

### VM1

```bash
cd /path/to/GP/Controller
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
```

### VM2

```bash
cd "/path/to/GP/SDN Topology"
sudo python3 topology.py
```

### Mininet CLI

```python
py net.pingall()
py net._bump_conntrack()
py net.start_background_traffic(net)
py net.wait(net, 60)   # let baselines mature
```

### Test A — Snort (5 min)

```python
py net.detect_on(net)
```

```bash
# VM1 shell
echo -n "CONTROL:ML:OFF" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:AUTHORIZE:0.90" | nc -u -w1 192.168.1.19 9999
```

```python
py net.launch_attack(net, 'sta1', 'icmp', duration=30, settle=10)
# Watch VM1: Snort SID 1000001 + BLOCKED box
py net.launch_attack(net, 'sta1', 'syn', duration=30, settle=10)
```

### Test B — RF (10 min)

```python
py net.detect_off(net)
```

```bash
echo -n "CONTROL:ML:OBSERVE" | nc -u -w1 192.168.1.19 9999
```

```python
py net.launch_attack(net, 'sta1', 'syn', duration=60, settle=15)
# Watch VM1: [ML-OBSERVE] verdict=SYN Flood conf=...
py net.launch_attack(net, 'sta1', 'icmp', duration=60, settle=15)
```

### Test C — AE (same session, read different log prefix)

```python
# Still DETECT OFF + ML OBSERVE — no change needed
py net.launch_attack(net, 'h1', 'udp', duration=60, settle=15)
# Watch VM1: [AE-OBSERVE] anomaly conf=... band=...
```

### Test D — Blocking (5 min)

```bash
echo -n "CONTROL:ML:AUTHORIZE:0.90" | nc -u -w1 192.168.1.19 9999
```

```python
py net.launch_attack(net, 'sta1', 'cps', duration=60, settle=15)
```

```bash
echo -n "CONTROL:UNBLOCK:10.0.0.1" | nc -u -w1 192.168.1.19 9999
echo -n "CONTROL:ML:OBSERVE" | nc -u -w1 192.168.1.19 9999
```

---

## Part 8 — Files to inspect after tests

| Artifact | Location | What it proves |
|---|---|---|
| Live controller log | Terminal A (VM1) | Snort alerts, `[ML-OBSERVE]`, `[AE-OBSERVE]`, blocks |
| Snort alerts | `/var/log/snort/alert_json.txt` | Raw signature hits |
| Dataset rows | `Controller/dataset.csv` | Per-window labels, `snort_sid`, features |
| RF sanity | `verify_inference.py` output | Train/serve match |
| Blocked IPs (if using Controller_main) | `curl http://127.0.0.1:8080/ips/blocked` | REST path blocks |

Validate a saved session CSV:

```bash
cd /path/to/GP/Controller
python3 validate_dataset.py dataset_sessionX_icmp.csv
```

---

## Part 9 — PASS criteria summary

| Pipeline | PASS when |
|---|---|
| **Snort** | Correct SID/GID fires per attack; `attack_type` in CSV matches; block in AUTHORIZE |
| **RF** | `[ML-OBSERVE]` shows correct `verdict` with conf ≥ 0.80 on strong attacks; normal stays quiet |
| **AE** | `[AE-OBSERVE]` appears on attacks with conf ≥ 0.60; ~half of attack windows ≥ 0.73; normal silent |
| **Full stack** | Fastest tier blocks first; `CONTROL:UNBLOCK` restores host; rollback to capture-only works |

---

## Related docs

- `context_claude.md` — architecture and tier definitions
- `ml_test_and_t530_deploy_plan.md` — ML + t530 deployment
- `t530_Deployment_and_Test_Plan.md` — staged lab → t530 → real network
- `docs/SNORT_RYU_INTEGRATION.md` — standalone Snort/bridge path (optional)
- `Controller/snort3/sdn_ips_local.rules` — signature SIDs 1000001–1000004
