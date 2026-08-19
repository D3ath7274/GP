# Adaptive Multi-Tier IPS for IoT over SD-WAN

A software-defined intrusion **prevention** system for IoT networks. A single merged
Ryu OpenFlow controller runs **four detection tiers** — Snort 3 signatures, rate
counters + Dynamic ARP Inspection, a Random Forest classifier, and an Autoencoder for
zero-day anomalies — and enforces mitigation with high-priority **OpenFlow DROP** rules
(plus host `iptables` for off-LAN sources). It ships with a REST API and a
dependency-free operator dashboard, and runs on constrained, edge-class hardware
(validated on an HP t530 thin client).

Detection is **agentless** (nothing installed on the IoT devices) and
**privacy-preserving** — the tiers score flow statistics and entropy, never packet
payloads.

---

## Status

A working research prototype with real deployment engineering — roughly **TRL 4–5**:
validated in a relevant lab environment, early field transition. Not a hardened
commercial product.

> ⚠️ **The shipped models were trained on a Mininet testbed** (which double-counted
> packets via a 2× mirror). Real phone/camera/sensor traffic looks nothing like that.
> **Collect real traffic and retrain before you enable blocking**, or the IPS will
> false-positive on legitimate devices. See
> [`pre_production_collection_runbook.md`](pre_production_collection_runbook.md).
> This is the single biggest false-positive fix, and it is not optional.

The repo contains the **deployment set only** — the IPS runtime, models, dashboard, and
the operation/test runbooks. The Mininet testbed (`SDN Topology/topology.py`), the QoS
traffic-steering app, the training notebooks, and the raw datasets were removed in
`8a07efc` and remain recoverable from the git history before that commit.

---

## Where it sits in the network

The controller only sees traffic that **physically crosses a switch it manages**, so
placement is the first deployment decision — and it determines whether the system can
block at all.

| Mode | How | Blocking | Best for |
|---|---|---|---|
| **A. Inline bridge / gateway** | t530 with **2 NICs** runs OVS as an L2 bridge between the LAN switch/AP and the router; all traffic transits it | ✅ OpenFlow DROP | whole-network, factory |
| **B. t530 as the Wi-Fi AP** | t530 runs `hostapd` + OVS; devices associate directly to it | ✅ OpenFlow DROP, per-device MAC | **"attach any device"**, smart-home |
| C. SPAN / mirror | a managed switch mirrors to the t530 | ❌ detect-only (enforce via switch ACL / RADIUS) | when you can't touch the switch |

**Mode B is the recommended starting point** — the t530 becomes the AP everything joins,
so it sees every device's real MAC and every packet, and MAC-based `dl_src` DROP works
natively. Setup: [`t530_mode_b_ap_setup.md`](t530_mode_b_ap_setup.md).

Note the visibility limit that follows: two devices on the same dumb switch behind the
t530 talk **east-west** without crossing it, and are invisible to every tier.

---

## Architecture (Mode B shown)

```
        phones · cameras · any-vendor IoT · (authorized attacker box)
                               │  Wi-Fi / LAN
                               ▼
┌───────────────────────────────────────────────────────────────────┐
│  HP t530 — controller + data path  (Ubuntu 22.04, Python 3.10)    │
│                                                                   │
│   OVS bridge (br-lan)  ── every packet mirrored to CONTROLLER ─┐  │
│        │                                                        │  │
│        │              OpenFlow 1.0 :6633                        │  │
│        ▼                                                        ▼  │
│   Controller/Controller_main_Claude.py   (one Ryu process)         │
│    ├─ Tier 1  Snort 3 signatures         snort_monitor.py          │
│    ├─ Tier 2  rate counters + DAI        traffic_capture.py        │
│    ├─ Tier 3  Random Forest              ml_inference.py           │
│    ├─ Tier 4  Autoencoder (pure-NumPy)   ae_inference.py           │
│    ├─ Enforcement:  OpenFlow DROP (dl_src)  ·  iptables (off-LAN)  │
│    └─ REST API + dashboard :8081   ·   UDP control :9999           │
│                               │ NAT (MASQUERADE)                   │
│                           enp1s0 ──▶ router / internet             │
└───────────────────────────────────────────────────────────────────┘
```

The feature extractor is fed by OpenFlow `packet_in`, so the tiers see **any** flow
crossing an OVS switch the controller manages — not just a fixed testbed.

---

## The four tiers (block if ANY tier fires, in AUTHORIZE mode)

| Tier | Engine | Detects | Blind spot (covered by the others) |
|---|---|---|---|
| 1 | Snort 3 signatures | known attack patterns | unknown / zero-day, no signature |
| 2 | Rate counters + DAI | volumetric floods, port scan, ARP spoof | low-and-slow, non-volumetric |
| 3 | Random Forest | names the attack class (7 classes) | classes absent from training |
| 4 | Autoencoder | zero-day / unknown anomalies | attacks mimicking normal; threshold-sensitive |

Tier 2 confirms only after **N consecutive windows** (hysteresis). Tier 3 is a supervised
sklearn pipeline (SMOTE + balanced weights); Tier 4 is a pure-NumPy `60→64→16→64→60`
autoencoder trained on **normal traffic only**.

**Confidence banding:** `conf < flag` → silent · flag band → evidence only · **block band**
→ OpenFlow DROP (RF block ≥ 0.80, AE block ≥ 0.73; AE conf = `error / (error + threshold)`,
threshold ≈ 0.482).

---

## Prerequisites

Ubuntu 22.04, Python 3.10, Ryu 4.34, **Snort 3 built from source**
(`/usr/local/bin/snort` — *not* the apt v2 package), scikit-learn 1.6.1,
imbalanced-learn, NumPy, `psutil`, Open vSwitch. Mode B additionally needs `hostapd`,
`dnsmasq`, `iw`, `iptables`, and an **AP-capable** Wi-Fi radio (Intel AC 3168/8265 often
cannot do AP mode — a USB adapter with an Atheros/MediaTek chipset is the reliable path).

nginx typically holds :8080, so the controller serves on **:8081**.

> Full clean-machine install (deps, Snort 3 build, bridge, systemd units) is in
> `SDN_IPS_Snort_Installation_Runbook.pdf`.

---

## Configuration — `Controller/ips_config.json`

Deployment settings are config-driven; missing or invalid keys fall back to
testbed-safe defaults.

```json
{
  "lan_cidr":       "192.168.50.0/24",
  "ext_whitelist":  ["127.0.0.1", "::1", "192.168.50.1"],
  "protected_macs": ["aa:bb:cc:dd:ee:ff"]
}
```

| Key | Meaning |
|---|---|
| `lan_cidr` | What counts as **internal**. Anything outside it is "external" and enforced via host `iptables` rather than OpenFlow. Default `10.0.0.0/8` — **set this to your real subnet** or your own devices get treated as outsiders. |
| `ext_whitelist` | Never iptables-block these — put your **gateway, controller, and admin host** here. Also extended by `IPS_MGMT_WHITELIST`. |
| `protected_macs` | Never-block list (router, owner's phone, critical sensors). Guards both the tier path and the REST path. |

---

## Quick start

**1. Launch the controller** (leave running):
```bash
cd Controller
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=enp1s0,snort_tap IPS_V2_FEATURES=1 \
  python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
  Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
```
`IPS_V2_FEATURES=1` is **required** or the v2 feature schema isn't emitted (the banner must
read `Feature schema mode: v2 (corrected)`). The startup banner should confirm all four
tiers loaded (AE threshold ≈ 0.482, RF pipeline, Snort PID, `Forced n_jobs=1`).

**2. Dashboard** — open `http://<controller-ip>:8081/`.

**3. Verify the data path** — `GET /ips/switches` should be `1` and `dataset.csv` must be
growing. (`pingall` or working internet does *not* prove the controller sees traffic — OVS
fail-mode forwards on its own.)

### Launch environment variables

| Variable | Effect |
|---|---|
| `IPS_V2_FEATURES=1` | **Required.** Emit the 102-column v2 feature schema. |
| `SNORT_PHYS_IFACE` / `SNORT_IFACES` | Physical NIC / the interface list Snort watches. |
| `IPS_NO_TAP=1` | Skip the TAP injection path (when Snort reads a real bridge). |
| `IPS_EXTERNAL_BLOCK=1` | Auto-block off-LAN attackers via host `iptables`. |
| `IPS_MGMT_WHITELIST=<ip>` | Extra never-iptables-block address (whitelist your admin host). |
| `IPS_BLOCK_SECONDS=<n>` | Timed blocks instead of permanent. |
| `IPS_HOST` / `IPS_PORT` | Bind address / port for REST + dashboard. |

---

## Before you enable blocking

The order matters. Do not skip to AUTHORIZE.

1. **Get inline** — Mode A or B ([`real_world_deployment_plan.md`](real_world_deployment_plan.md),
   [`t530_mode_b_ap_setup.md`](t530_mode_b_ap_setup.md)).
2. **Set `ips_config.json`** for your real subnet, gateway, and protected devices.
3. **Collect real normal traffic** in capture-only mode and register every host, then
   **retrain** — [`pre_production_collection_runbook.md`](pre_production_collection_runbook.md).
   Retrain the RF with `Controller/ml_models/retrain_rf_v4.py` (preserves the exact feature
   schema, so the output is a drop-in `rf_pipeline.joblib`); rebuild the AE bundle with
   `build_ae_bundle.py`.
4. **Recalibrate the Tier 1/2 thresholds** against your real baseline — the shipped numbers
   were tuned to the testbed's 2× mirror double-count.
5. **Run in OBSERVE** and confirm it does not flag your own devices.
6. **Only then AUTHORIZE.**

---

## Operating modes & control channel

Detection and enforcement are toggled out-of-band over UDP 9999 with `Controller/ipsctl.py`
(reaches the controller even under a flood):

```bash
python3 ipsctl.py CONTROL:DETECT:ON|OFF                  # Tier 1/2 (Snort + rate/DAI) enforcement
python3 ipsctl.py CONTROL:ML:OFF|OBSERVE|AUTHORIZE[:thr] # Tier 3/4 (RF+AE): idle / log-only / blocking
python3 ipsctl.py CONTROL:ML:RF:ON|OFF                   # isolate a tier (RF alone / AE alone)
python3 ipsctl.py CONTROL:ML:AE:ON|OFF
python3 ipsctl.py CONTROL:ML:AE:BLOCK:0.85               # tune the AE block band live
python3 ipsctl.py CONTROL:ML:DEFER:ON|OFF                # AE stays silent on RF-known attacks
python3 ipsctl.py CONTROL:UNBLOCK:<ip>                   # release a blocked host
python3 ipsctl.py CONTROL:CLEAR[:ip]                     # reset confirmed-attacker state
```

- **DETECT** gates the signature/rate/DAI tiers; **ML mode** gates RF/AE. So
  `DETECT:OFF + ML:AUTHORIZE` isolates the RF/AE tiers, `DETECT:ON + ML:OFF` tests
  Snort/rate alone, and `DETECT:ON + ML:AUTHORIZE` is the full stack.
- **OBSERVE** logs verdicts without blocking — use it to validate accuracy before authorizing.
- **Blocks are permanent by default** (OpenFlow DROP with no hard timeout, until
  `CONTROL:UNBLOCK`); set `IPS_BLOCK_SECONDS=<n>` at launch for auto-expiring blocks.

**Host registration** (naming devices for the dataset and dashboard):
```bash
python3 ipsctl.py REGISTER:NAME:frontcam:192.168.50.60
python3 ipsctl.py REGISTER:IOT:192.168.50.60:IOT:Camera
```

> `LABEL_OVERRIDE`, `ATTACK_START/STOP`, `MININET_EVENT`, and `CONTROL:ROTATE` are
> **dataset-collection commands** — used during the learning phase, not in production.

---

## Validation & testing

| Doc | What it covers |
|---|---|
| [`red_team_test_runbook.md`](red_team_test_runbook.md) | Per-tier attack mechanics — proving each tier actually **blocks** a live attack (ICMP/SYN/UDP flood, CPS, port scan, ARP spoof) from an authorized attacker box. |
| [`production_readiness_test_plan.md`](production_readiness_test_plan.md) | The POC campaign a company would run: false positives on real users, throughput on real hardware, evasion, operability — with KPIs. |
| [`production_readiness_results.md`](production_readiness_results.md) | Results sheet to fill in as you run the plan. |

Run these only against systems you own and are authorized to test.

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

> These numbers were tuned against the testbed's 2× mirror. **Recalibrate them on your real
> baseline** — real traffic isn't double-counted, so they will mis-fire.

---

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

## Documentation map

| Doc | Read it when |
|---|---|
| [`t530_full_system_runbook.md`](t530_full_system_runbook.md) | **Single source of truth for operation** — install → run → test every tier → dashboard. |
| [`real_world_deployment_plan.md`](real_world_deployment_plan.md) | Moving off the testbed: what assumes Mininet and must change, plus a phased rollout. |
| [`t530_mode_b_ap_setup.md`](t530_mode_b_ap_setup.md) | Standing up the t530 as the Wi-Fi AP (hostapd + OVS + NAT). |
| [`t530_bridge_setup.md`](t530_bridge_setup.md) | Throwaway VXLAN mirror so Snort can see a lab VM's data plane. |
| [`pre_production_collection_runbook.md`](pre_production_collection_runbook.md) | Collecting real-network data and retraining before enabling blocking. |
| `SDN_IPS_Snort_Installation_Runbook.pdf` | Full clean-machine install incl. the Snort 3 source build. |
| [`AI_Project_Context.md`](AI_Project_Context.md) | Dense technical index of the whole system. |
| [`docs/SNORT_RYU_INTEGRATION.md`](docs/SNORT_RYU_INTEGRATION.md) | The standalone Snort→Ryu path (separate from the merged controller). |

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
│   ├── traffic_mirror.py          # TAP interface — injects packet_in copies for Snort
│   ├── ipsctl.py                  # UDP-9999 control command sender
│   ├── ips_config.json            # deployment config (lan_cidr, whitelist, protected MACs)
│   ├── snort_ryu_bridge.py / snort_alert_reader.py  # standalone Snort→Ryu path
│   ├── ml_models/                 # rf_pipeline.joblib, ae_bundle.joblib, retrain + build scripts
│   ├── snort3/                    # sdn_ips_local.rules, sdn_ips.lua
│   └── scripts/                   # Snort install/start, VXLAN bridge, offloads, verification
├── Dashboard/index.html           # operator dashboard (zero-dependency, served at :8081/)
├── docs/SNORT_RYU_INTEGRATION.md  # standalone Snort→Ryu integration notes
├── AI_Project_Context.md          # dense technical index of the whole system
├── real_world_deployment_plan.md  # testbed → real network migration plan
├── pre_production_collection_runbook.md   # collect real traffic + retrain
├── t530_full_system_runbook.md    # single end-to-end run/test runbook
├── t530_mode_b_ap_setup.md        # t530 as Wi-Fi AP (hostapd + OVS)
├── t530_bridge_setup.md           # temporary VXLAN mirror for lab testing
├── red_team_test_runbook.md       # per-tier blocking validation
├── production_readiness_test_plan.md / _results.md   # POC campaign + KPI scorecard
└── README.md                      # this file
```

---

## Known limitations

| Limitation | What it means |
|---|---|
| **No application-layer (L7) inspection** | Blind to SQLi, XSS, RCE, path traversal — they ride valid TCP flows. Pair with a WAF. |
| **Encrypted traffic is opaque** | No TLS payload inspection; metadata and behavior only. |
| **East-west blind spot** | Devices on the same dumb switch behind the t530 never cross it. |
| **Single controller = SPOF** | No HA or clustering. Decide fail-open (no protection) vs fail-closed (no traffic) deliberately. |
| **Scale ceiling** | Ryu on one thin client, packet-in-to-controller ML, RF forced to `n_jobs=1` — SMB/branch scale, not datacenter. |
| **Legacy OpenFlow 1.0** | Limited match fields and IPv6 richness; MAC/IP DROP can be evaded by spoofing the identifier. |
| **Models need retraining per site** | Shipped models are testbed-trained; RF only recognizes labeled classes and drifts as traffic evolves. |
| **Adversarial robustness untested** | Low-and-slow, traffic mimicry, spoofing, and baseline poisoning during the learning window are not specifically hardened against. |
| **Manual MLOps** | Pinned scikit-learn, Snort 3 from source, eventlet quirks; no automated model lifecycle. |

---

## Troubleshooting

| Problem | Solution |
|---|---|
| ML/AE silent, `dataset.csv` not growing | No `packet_in` — wrong controller IP / switch not connected. Verify `GET /ips/switches` = 1. `pingall` still works via OVS fail-mode, so it is not proof. |
| Controller hangs when ML is armed | Keep sklearn `n_jobs=1` (banner: `Forced n_jobs=1`). Multiprocessing pools deadlock under eventlet. |
| Snort is v2 / wrong SIDs | Use Snort 3 from source (`/usr/local/bin/snort`); `apt install snort` is v2 and unsupported. |
| Bridge posts blocks to `:8080` (nginx 404) | The controller is on **:8081**; set `RYU_API_URL=http://127.0.0.1:8081/ips/block`. |
| A blocked host never recovers | Blocks are permanent by default — release with `CONTROL:UNBLOCK:<ip>` (not just `CLEAR`). |
| Your own devices get iptables-blocked | `lan_cidr` still defaults to `10.0.0.0/8` — set it to your real subnet in `ips_config.json`. |
| ARP spoof not detected | The real device must have sent traffic first so a binding exists. |
| Wi-Fi clients associate but pass no traffic (Mode B) | Intel AP-mode driver limitation — use an AP-capable USB adapter (Atheros/MediaTek). |
| Snort decoder alerts: `IPv4 datagram length > captured length` | Run `Controller/scripts/disable_capture_offloads.sh`. |
| Dashboard GET requests flood the console | They are redirected to `GET_log.txt`. |
