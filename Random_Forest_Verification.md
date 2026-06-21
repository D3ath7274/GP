# Random Forest Verification — Step-by-Step Plan

**Goal:** generate a fresh dataset on the live 2-VM setup (Mininet topology +
Ryu controller) and verify that your friend's `final_rf_model.joblib` still
detects attacks correctly on data it has never seen.

**Environments:**
- **Controller VM** — Ubuntu, runs Ryu (`Controller.py`) + the traffic capture
  that writes the CSV. Physical IP `192.168.1.19` (per `topology.py`).
- **Topology VM** — Ubuntu, runs Mininet-WiFi (`topology.py`).
- **Model host** — where `ML model/final_rf_model.joblib`, `scaler.joblib`, and
  `test_model.py` live (your Windows repo). You run the scoring there.

---

## ⚠️ Read before you start (things that will save you)

1. **We score with the full pipeline (`full_ml_pipeline.joblib`), not the bare
   model.** The pipeline is your friend's authoritative artifact: it does ALL
   preprocessing internally (drop columns → one-hot `protocol` → StandardScaler →
   RandomForest), so you feed it the **raw** CSV and it returns predictions. This
   removes the "did I scale it right?" risk entirely. (`test_model.py` already
   does this.)

2. **Label mapping is fixed and hardcoded — do not recompute it.** The pipeline's
   classes are in *insertion order* (`0=normal, 1=ICMP Flood, 2=SYN Flood,
   3=ARP Spoofing, 4=UDP Flood, 5=Port Scan, 6=Control Plane Saturation`),
   verified against the model itself. Your friend's snippet rebuilds this map
   from the new CSV via `pd.unique()`, which is **row-order dependent** and will
   mislabel everything if your new data's rows are ordered differently.
   `test_model.py` hardcodes the correct map, so use it.

3. **Run capture in v1-compatible mode (the default) — this is critical.** The
   capture bug-fixes change model-visible features (`fwd_bwd_packet_ratio`,
   `fwd_bwd_bytes_ratio`, `unique_dst_ports`) that the friend's model depends on.
   Feeding it the *corrected* values makes it miss attacks — we measured **0%
   ICMP-flood recall** on a v2-captured dataset, because `fwd_bwd_bytes_ratio`
   for a flood collapsed from ~172,000 (training) to ~1.0. So capture now defaults
   to **v1-compatible mode**, reproducing the training-time feature behaviour.
   **Do NOT set `IPS_V2_FEATURES=1`** for this verification — that mode is only for
   collecting data to *retrain* a new (v2) model later. If you already captured a
   dataset before this fix, **discard it and re-capture.**

---

## Part A — Controller VM: start the controller & capture

```bash
# On the CONTROLLER VM
cd <repo>/Controller

# launch the Ryu controller (this also starts traffic capture -> dataset.csv)
ryu-manager Controller.py
```

> **No ML deps needed on the Controller VM for verification.** Data collection
> runs with ML mode OFF (the default) — labels come from detection mode + rate
> counters, not the model. The controller imports its ML engine lazily and starts
> fine even if scikit-learn/pandas aren't installed (it just logs "ML inference
> disabled"). You score the captured data later on the model host (Part F).

Confirm in the log that you see:
- `UDP command listener started on port 9999`
- `Traffic capture started → dataset.csv`

The capture file is written to **`Controller/dataset.csv`** (relative to where you
launched `ryu-manager`). Leave this terminal running.

> If `192.168.1.19` is **not** the controller VM's real IP, edit `CONTROLLER_IP`
> at the top of `topology.py` to match before starting the topology, or the
> detection-toggle UDP commands won't reach the controller.

---

## Part B — Topology VM: bring up the network

```bash
# On the TOPOLOGY VM (Mininet needs root)
cd <repo>/SDN\ Topology
sudo python3 topology.py
```

Wait for `*** Running CLI` and the `mininet-wifi>` prompt. Confirm the switch
connected to the controller (the controller log shows a datapath join, and
`*** All hostnames registered with controller`).

Sanity-check connectivity from the Mininet CLI:
```text
mininet-wifi> pingall
```

---

## Part C — Generate NORMAL traffic (the clean baseline)

In the **Mininet CLI** (Topology VM), first **register the two IoT devices** so
the node mix matches the training dataset. They are NOT created by default, and
`start_background_traffic` only starts their telemetry if they exist by name:

```text
mininet-wifi> py net.register_iot_device(net, 'TempSensor', '10.0.0.5/24', '00:00:00:00:00:05', 's1', 'IOT:TempSensor')
mininet-wifi> py net.register_iot_device(net, 'Cam', '10.0.0.6/24', '00:00:00:00:00:06', 's1', 'IOT:Camera')
```

Confirm they appear (you should now see `Cam` and `TempSensor`):
```text
mininet-wifi> nodes
```

> IoT devices are dynamic — re-register them on every fresh run. The MAC OUI
> `00:00:00` matches the dataset; the registration also pushes `REGISTER:IOT:*`
> to the controller so the device-behavioral features populate for these hosts.

Then start the clean baseline:

```text
mininet-wifi> py net.detect_off(net)
mininet-wifi> py net.start_background_traffic(net)
```

- `detect_off` → all rows are labeled `normal` (clean data).
- `start_background_traffic` → HTTP browsing, iperf, pings, and the TempSensor /
  Cam IoT heartbeats.

**Let it run for at least 3–4 minutes.** The device baselines only become
"mature" after 180 s (`is_baseline_mature` flips to 1), and you want a few
hundred normal windows before you introduce attacks.

*(Optional, to test surge-tolerance later with the anomaly model: from the CLI
run a big transfer, e.g. `sta1 iperf -c 10.0.0.4 -p 5001 -t 20`. For RF
verification it's not required.)*

---

## Part D — Generate ATTACK traffic (labeled)

> **CRITICAL — attackers must have a CLEAN device profile, or the model misses
> everything.** The friend's model keys heavily on the *attacker's device profile*
> (`device_protocol_dist_*`, `device_avg_pkt_rate`, …). In training, each attack
> came from a profile-clean, attack-dominated host. We proved that when the
> attacker is *also* running heavy background traffic (web browsing + iperf), its
> profile shifts and the model gets **0% recall** — substituting a clean profile
> flips the same rows to **100%**. So **do not launch attacks from a host that is
> generating heavy normal traffic.** Either run `start_background_traffic` only on
> the *non-attacker* hosts, or use dedicated attacker hosts. (This brittleness is
> itself a key finding — see the note at the end — and is exactly what the
> anomaly-detector layer is meant to cover.)

Turn detection **ON** so the controller labels attack rows with their type
(`attack_type`), which is what lets `test_model.py` produce a scored report:

```text
mininet-wifi> py net.detect_on(net)
```

**Signal each attack to the controller** so the metadata columns
(`meta_attack_tool`, `meta_attack_intensity`) are filled — wrap every attack in
`attack_start` / `attack_stop`. `timeout 20` bounds each attack to ~20 s (≈4
windows — enough for consecutive-window confirmation). **Run them one at a time,
pausing ~10 s between** so the detector settles.

```text
# ICMP Flood            (sta1 -> h2)
mininet-wifi> py net.attack_start(net, 'hping3', 'icmp-flood')
mininet-wifi> sta1 timeout 20 hping3 --icmp --flood 10.0.0.4
mininet-wifi> py net.attack_stop(net)

# SYN Flood             (sta1 -> h2:80)
mininet-wifi> py net.attack_start(net, 'hping3', 'syn-flood')
mininet-wifi> sta1 timeout 20 hping3 -S --flood -p 80 10.0.0.4
mininet-wifi> py net.attack_stop(net)

# UDP Flood             (sta1 -> h2:53)
mininet-wifi> py net.attack_start(net, 'hping3', 'udp-flood')
mininet-wifi> sta1 timeout 20 hping3 --udp --flood -p 53 10.0.0.4
mininet-wifi> py net.attack_stop(net)

# Control Plane Saturation  (UDP to incrementing dst ports -> many flows)
mininet-wifi> py net.attack_start(net, 'hping3', 'cps')
mininet-wifi> sta1 timeout 20 hping3 --udp --flood -p ++1 10.0.0.4
mininet-wifi> py net.attack_stop(net)

# Port Scan             (sta2 -> h2, sequential)
mininet-wifi> py net.attack_start(net, 'nmap', 'port-scan')
mininet-wifi> sta2 timeout 20 nmap -sS -p 1-1000 10.0.0.4
mininet-wifi> py net.attack_stop(net)

# ARP Spoofing          (sta2 poisons h2's view of h1)
mininet-wifi> py net.attack_start(net, 'arpspoof', 'arp-spoof')
mininet-wifi> sta2 timeout 20 arpspoof -i sta2-wlan0 -t 10.0.0.4 10.0.0.3
mininet-wifi> py net.attack_stop(net)
```

Watch the **controller log** — you should see the Snort/DAI alerts plus
`SUSPECTED ATTACK` → `ATTACK CONFIRMED` lines naming each source/type.

> **Labels are now protocol-correct.** A prior bug let an ICMP-flood Snort alert
> tag the attacker's *TCP/ARP background* traffic as "ICMP Flood" too. That guard
> is fixed, so only protocol-matching flows get the attack label. `attack_start`
> fills audit metadata only — it does **not** change labels. For a stealthy
> attack that stays below detection thresholds, you can force its label with
> `py net.label_attacker(net, '10.0.0.1', 'Port Scan')` (then `…, 'clear'`), but
> note it labels *all* protocols from that IP, so only use it on a host sending
> nothing but the attack.

> Interface names in Mininet-WiFi: stations are `sta1-wlan0` / `sta2-wlan0`,
> wired hosts are `h1-eth0` / `h2-eth0`. Adjust the `arpspoof -i` interface if
> you launch it from a different node.

*(Optional zero-day style probe for later: a slow scan `sta2 nmap -T1 -p 1-200
10.0.0.4` — the RF may miss it; that's expected and is the autoencoder's job.)*

---

## Part E — Stop and collect the dataset

1. In the Mininet CLI: `exit` (this calls `net.stop()`).
2. In the controller terminal: `Ctrl-C` to stop Ryu — capture flushes remaining
   rows and logs `Total rows written: N`.
3. The dataset is at **`Controller/dataset.csv`** on the Controller VM.

Copy it to the model host (Windows repo). Pick one:

```bash
# from the model host, pull it off the controller VM
scp user@192.168.1.19:<repo>/Controller/dataset.csv  "D:/4th Year/Graduation Project/data/Claude Code Magic/GP/ML dataset/new_test.csv"
```
*(or use a VM shared folder / VirtualBox guest additions mount.)*

---

## Part F — Score the model

On the **model host** (where `ML model/` lives). First-time deps:

```bash
pip install scikit-learn==1.6.1 imbalanced-learn   # 1.6.1 = the version it was pickled with
```
*(`imbalanced-learn` is required because the pipeline bundles a SMOTE step;
`ML model/column_dropper.py` must sit next to the pipeline so it can unpickle —
it already does.)*

```bash
cd "D:/4th Year/Graduation Project/data/Claude Code Magic/GP"
python "ML model/test_model.py" "ML dataset/new_test.csv"
```

What it does:
- loads `full_ml_pipeline.joblib` (registers `ColumnDropper`, needs `imblearn`),
- feeds your **raw** CSV straight in — the pipeline drops columns, one-hot encodes
  `protocol`, and StandardScales internally,
- maps the numeric output through the **hardcoded insertion-order** label map,
- writes `..._predictions.csv` next to your input,
- prints a **scored report** (accuracy, per-class precision/recall, confusion
  matrix) because your CSV has the `attack_type` column.

> Sanity reference: on `dataset_final.csv` this prints **99.89%** with all six
> attack classes at 94–100% recall. Your fresh-data numbers should be in the same
> ballpark if the model generalizes.

---

## Interpreting the results

- **Per-class recall** = did the model catch each attack type on fresh data?
  This is the headline number for verification. Compare against the friend's
  reported numbers.
- **Confusion matrix** = where it confuses one attack for another.
- **Normal precision / false positives** = how often benign traffic got flagged.
  A modest rise here vs. the friend's numbers is the expected effect of the
  capture-code caveat (§2) — not a model failure.

**Good result:** high recall on all six attack types (the friend saw ~95–100%),
normal mostly classified normal.

**If every attack reads "normal" (and normal recall ≈ 100%):** you scored raw,
unscaled data through the bare model instead of the pipeline. Use
`test_model.py` (it routes through `full_ml_pipeline.joblib`, which scales
internally).

**If attack types look scrambled** (e.g. SYN flicks predicted as ARP): a wrong
label map. `test_model.py` hardcodes the correct insertion-order map — don't
substitute a `pd.unique()`-derived one.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Switch never connects, no datapath in controller log | wrong `CONTROLLER_IP` or firewall on :6633 | fix `CONTROLLER_IP` in `topology.py`; allow TCP 6633 on Controller VM |
| `detect_on/off` has no effect | UDP :9999 blocked between VMs | allow UDP 9999 to the Controller VM; confirm `CONTROLLER_IP` |
| Attacks not labeled (all rows `normal`) | detection was OFF during attacks | run `py net.detect_on(net)` **before** the attacks |
| `dataset.csv` empty / few rows | topology produced no traffic, or capture not started | confirm `start_background_traffic` ran; check controller log for capture start |
| `test_model.py` error during prediction (missing columns) | CSV schema differs from `dataset_final.csv` | ensure you used this repo's `traffic_capture.py`; don't hand-edit columns |
| `ModuleNotFoundError: imblearn` | pipeline needs imbalanced-learn | `pip install imbalanced-learn` on the scoring host |
| `AttributeError: Can't get attribute 'ColumnDropper'` | custom class not registered before load | keep `ML model/column_dropper.py` next to the pipeline; `test_model.py` imports it automatically |
| Version warning on model load | sklearn ≠ 1.6.1 | `pip install scikit-learn==1.6.1` on the scoring host |

---

## One-glance checklist

- [ ] Controller VM: `ryu-manager Controller.py` running, capture started
- [ ] Capture in **v1-compatible mode** (default; do NOT set `IPS_V2_FEATURES=1`); log says "Feature schema mode: v1-compatible"
- [ ] `CONTROLLER_IP` in `topology.py` matches the Controller VM
- [ ] Topology VM: `sudo python3 topology.py`, switch connected, `pingall` OK
- [ ] Register IoT devices (TempSensor 10.0.0.5, Cam 10.0.0.6) → confirm with `nodes`
- [ ] `detect_off` → `start_background_traffic` → wait ≥ 3 min (baseline matures)
- [ ] `detect_on` → for each of the 6 attacks: `attack_start` → run (`timeout 20`) → `attack_stop`
- [ ] Controller log shows Snort/DAI alert + `ATTACK CONFIRMED` for each
- [ ] `exit` topology, `Ctrl-C` controller → collect `Controller/dataset.csv`
- [ ] Copy CSV to model host → `python "ML model/test_model.py" <csv>`
- [ ] Read per-class recall + confusion matrix
