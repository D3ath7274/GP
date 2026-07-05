# Adaptive IPS for IoT over SD-WAN

A software-defined intrusion **prevention** system for IoT networks. A single merged
Ryu OpenFlow controller runs **four detection tiers** — Snort 3 signatures, rate
counters + Dynamic ARP Inspection, a Random Forest classifier, and an Autoencoder for
zero-day anomalies — and enforces mitigation with high-priority **OpenFlow DROP** rules.
It ships with a REST API and a dependency-free operator dashboard, and is designed to run
on constrained, edge-class hardware (validated on an HP t530 thin client).

---

## Architecture

Two nodes on one LAN:

```
┌────────────────────────────────────────────────────────────┐
│  Controller node — HP t530 (Ubuntu 22.04, Python 3.10)       │
│  Controller/Controller_main_Claude.py  (one Ryu process)     │
│   ├─ Tier 1  Snort 3 signatures        (snort_monitor.py)    │
│   ├─ Tier 2  rate counters + DAI       (traffic_capture.py)  │
│   ├─ Tier 3  Random Forest             (ml_inference.py)     │
│   ├─ Tier 4  Autoencoder (pure-NumPy)  (ae_inference.py)     │
│   ├─ OpenFlow DROP enforcement                               │
│   └─ REST API + dashboard  (:8081)  ·  UDP control (:9999)   │
└────────────────────────────────────────────────────────────┘
        │ OpenFlow (TCP 6633)   │ UDP control (9999)   │ REST/dashboard (8081)
┌────────────────────────────────────────────────────────────┐
│  Topology node — Mininet-WiFi VM (SDN Topology/topology.py)  │
│   OVS switch s1 · AP ap1 · sta1/sta2 (WiFi) · h1/h2 (wired)  │
│   IoT: TempSensor (10.0.0.5), Cam (10.0.0.6)                 │
│   Every packet mirrored to the controller (output:CONTROLLER)│
└────────────────────────────────────────────────────────────┘
```

The feature extractor is fed by OpenFlow `packet_in`, so the tiers see **any** flow
crossing an OVS switch — internal or external-in-transit — not just a fixed testbed.

---

## The four tiers (block if ANY tier fires, in AUTHORIZE mode)

| Tier | Engine | Detects | Notes |
|---|---|---|---|
| 1 | Snort 3 signatures | the 6 known attacks | fast, high-precision; blind to the unseen |
| 2 | Rate counters + DAI | volumetric floods, port scan, ARP spoof | confirms only after **N consecutive windows** (hysteresis) |
| 3 | Random Forest | names the attack class (7 classes) | supervised sklearn pipeline (SMOTE + balanced weights) |
| 4 | Autoencoder | zero-day / unknown anomalies | trained on **normal only**; pure-NumPy `60→64→16→64→60` |

**Confidence banding:** `conf < flag` → silent · flag band → evidence only · **block band**
→ OpenFlow DROP (RF block ≥ 0.80, AE block ≥ 0.73; AE conf = `error / (error + threshold)`,
threshold ≈ 0.482).

---

## Prerequisites

**Controller node:** Ubuntu 22.04, Python 3.10, Ryu 4.34, **Snort 3 built from source**
(`/usr/local/bin/snort` — *not* the apt v2 package), scikit-learn 1.6.1, imbalanced-learn,
NumPy, `psutil`. nginx typically holds :8080, so the controller serves on **:8081**.

**Topology node:** Ubuntu 22.04, Mininet-WiFi, `hping3`, `nmap`, `dsniff` (arpspoof).

> Full clean-machine install (deps, Snort 3 build, VXLAN `br-snort` bridge, systemd units)
> is in `SDN_IPS_Snort_Installation_Runbook.pdf`. End-to-end run/test steps are in
> **`t530_full_system_runbook.md`** — the single source of truth for operation.

---

## Quick start

**1. Controller node** — one process (leave running):
```bash
cd Controller
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=enp1s0,snort_tap IPS_V2_FEATURES=1 \
  python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
  Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
```
`IPS_V2_FEATURES=1` is **required** or the v2 feature schema isn't emitted. The startup
banner should confirm all four tiers loaded (AE threshold ≈ 0.482, RF pipeline, Snort PID,
`Forced n_jobs=1`).

**2. Topology node** — targets the controller's IP:
```bash
cd "SDN Topology"
sudo python3 topology.py
```

**3. Dashboard** — open `http://<controller-ip>:8081/` in a browser.

**4. Verify the data path** — `GET /ips/switches` should be `1` and `dataset.csv` must be
growing. (`pingall` working does *not* prove the controller sees traffic — OVS fail-mode
forwards on its own.)

---

## Operating modes & control channel

Detection and enforcement are toggled out-of-band over UDP 9999 with `Controller/ipsctl.py`
(reaches the controller even under a flood):

```bash
python3 ipsctl.py CONTROL:DETECT:ON|OFF                 # Tier 1/2 (Snort + rate/DAI) enforcement
python3 ipsctl.py CONTROL:ML:OFF|OBSERVE|AUTHORIZE[:thr] # Tier 3/4 (RF+AE): idle / log-only / blocking
python3 ipsctl.py CONTROL:ML:RF:ON|OFF                   # isolate a tier (RF alone / AE alone)
python3 ipsctl.py CONTROL:ML:AE:ON|OFF
python3 ipsctl.py CONTROL:ML:AE:BLOCK:0.85              # tune the AE block band live
python3 ipsctl.py CONTROL:ML:DEFER:ON|OFF               # AE stays silent on RF-known attacks
python3 ipsctl.py CONTROL:UNBLOCK:<ip>                  # release a blocked host
python3 ipsctl.py CONTROL:CLEAR[:ip]                    # reset confirmed-attacker state
```

- **DETECT** gates the signature/rate/DAI tiers; **ML mode** gates RF/AE. So
  `DETECT:OFF + ML:AUTHORIZE` isolates the RF/AE tiers, `DETECT:ON + ML:OFF` tests
  Snort/rate alone, and `DETECT:ON + ML:AUTHORIZE` is the full stack.
- **OBSERVE** logs verdicts without blocking — use it to validate accuracy before authorizing.
- **Blocks are permanent by default** (OpenFlow DROP with no hard timeout, until
  `CONTROL:UNBLOCK`); set `IPS_BLOCK_SECONDS=<n>` at launch to restore auto-expiring blocks.

---

## Attack simulation

From the Mininet CLI (`mininet-wifi>`), on top of continuous background traffic:

```bash
sta1 hping3 --icmp --flood 10.0.0.4          # ICMP Flood
sta1 hping3 -S --flood -p 80 10.0.0.4        # SYN Flood
sta1 hping3 --udp --flood -p 53 10.0.0.4     # UDP Flood
sta1 hping3 --udp --flood -p ++1 10.0.0.4    # Control Plane Saturation (port-spread)
sta1 nmap  -sS -p 1-1000 10.0.0.4            # Port Scan
sta1 arpspoof -i sta1-wlan0 -t 10.0.0.4 10.0.0.1   # ARP Spoofing
```

Helpers: `py net.run_attack_session(net,'<kind>')`, `py net.run_full_attack_demo(net)`,
`py net.register_iot_device(...)`. Automated dataset collection:
`py net.run_full_collection_hy(net)`.

---

## Detection thresholds

**Tier 2 rate counters (per 5-second window, per host)** — confirmed only after N
consecutive windows (hysteresis):

| Attack | Rate-counter condition | N consecutive windows |
|---|---|---|
| ICMP Flood | ICMP count > 500 | 3 |
| SYN Flood | SYN-only > 300, low ACK, ≤ 10 dst ports | 2 |
| UDP Flood | UDP count > 500 (few dst ports) | 3 |
| Control Plane Saturation | UDP > 500 **and** > 100 dst ports | 3 (default) |
| Port Scan | > 100 unique dst ports, SYN-only | 2 |
| ARP Spoofing | IP→MAC binding mismatch | 1 (instant) |

A secondary Z-score check (threshold 8.0) catches attacks that stay just below the counters.

**Tier 1 Snort local rules** (`Controller/snort3/sdn_ips_local.rules`): ICMP `sid:1000001`
(500 pkts/5 s), SYN `sid:1000002` (2000/5 s), UDP `sid:1000003` (dst 53), CPS `sid:1000004`
(dst ≠ 53); Port Scan = `port_scan` inspector (GID 122); ARP = `arp_spoof` inspector (GID 112).

---

## Traffic steering (QoS) — `QoS/`

A companion **SD-WAN traffic-steering** app (`QoS/smart_controller.py`, OpenFlow 1.3) routes
priority traffic (e.g. IoT: MQTT/CoAP) down a **fast path** and everything else down a
**backup path**, per a customer policy in `config.json`, on a 4-switch dual-path topology
(`smart_topology.py`). It mirrors all edge traffic to the IPS server for inspection, so
steering and intrusion prevention compose. It runs as its own controller (separate from the
OF 1.0 IPS). See [QoS/README.md](QoS/README.md) for the path map, run commands, and the note
on wiring the real data-rate threshold.

## REST API (`:8081`)

`GET /` (dashboard) · `/ips/status` · `/ips/metrics` (per-tier + per-attack counts, confirmed
attackers, CPU/RAM/disk via psutil) · `/ips/alerts` · `/ips/blocked` · `/ips/switches` ·
`POST /ips/block` · `DELETE /ips/block/<ip>`.

---

## Output files

| File | Location | Contents |
|---|---|---|
| `dataset.csv` | `Controller/` | per-flow 5 s windows, 102-col v2 features + labels |
| `controller_run.log` | `Controller/` | full controller log (tee'd) |
| `GET_log.txt` | `Controller/` | dashboard HTTP access log (kept off the console) |
| Snort `alert_json` | `/var/log/snort/` | Snort 3 JSON alerts |

---

## Project structure

```
GP/
├── Controller/
│   ├── Controller_main_Claude.py  # merged Ryu controller (all 4 tiers + REST + control)
│   ├── traffic_capture.py         # packet_in → 5s windows → features → dataset + live inference
│   ├── snort_monitor.py           # Snort 3 launch + alert_json parse + (GID,SID) suppression
│   ├── ml_inference.py            # Tier 3 Random Forest engine
│   ├── ae_inference.py            # Tier 4 Autoencoder engine (pure-NumPy)
│   ├── ipsctl.py                  # UDP-9999 control command sender
│   ├── snort_ryu_bridge.py / snort_alert_reader.py  # standalone Snort→Ryu path
│   ├── ml_models/                 # rf_pipeline.joblib, ae_bundle.joblib, build_ae_bundle.py
│   └── snort3/                    # sdn_ips_local.rules, sdn_ips.lua
├── SDN Topology/topology.py       # Mininet-WiFi lab + attack/collection helpers
├── QoS/                           # adaptive traffic steering (SD-WAN fast/backup path)
│   ├── smart_controller.py        # OF 1.3 steering app (classify → policy → path + IPS mirror)
│   ├── smart_topology.py          # 4-switch dual-path SD-WAN topology
│   └── config.json                # customer policy (priority class + rate threshold)
├── Dashboard/index.html           # operator dashboard (zero-dependency, served at :8081/)
├── ML dataset/                    # dataset_v2/v4 master + training CSVs
├── AI_Project_Context.md          # dense technical index of the whole system
├── t530_full_system_runbook.md    # single end-to-end run/test runbook
└── README.md                      # this file
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| ML/AE silent, `dataset.csv` not growing | No `packet_in` — wrong controller IP / switch not connected. Verify `GET /ips/switches` = 1. `pingall` still works via OVS fail-mode, so it is not proof. |
| Controller hangs when ML is armed | Keep sklearn `n_jobs=1` (banner: `Forced n_jobs=1`). Multiprocessing pools deadlock under eventlet. |
| Snort is v2 / wrong SIDs | Use Snort 3 from source (`/usr/local/bin/snort`); `apt install snort` is v2 and unsupported. |
| Bridge posts blocks to `:8080` (nginx 404) | The controller is on **:8081**; set `RYU_API_URL=http://127.0.0.1:8081/ips/block`. |
| A blocked host never recovers | Blocks are permanent by default — release with `CONTROL:UNBLOCK:<ip>` (not just `CLEAR`). |
| ARP spoof not detected | The real device must have sent traffic first so a binding exists. |
| Dashboard GET requests flood the console | They are redirected to `GET_log.txt`. |
