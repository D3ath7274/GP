# Real-World Deployment Plan — turning the t530 IPS into a product for real networks

**Goal.** Deploy the t530 as a drop-in IPS on a **real** network (home / smart-home /
smart-factory) where real phones, cameras, and any-vendor IoT sensors connect over Wi-Fi/LAN,
and a Kali box on the same LAN plays the attacker. This document assesses **what in the code
assumes the Mininet testbed** and must be removed / changed / added, then gives a phased rollout.

**Authorization.** Your own network + your own Kali box, in your lab. Defensive validation only.

---

## 0. The #1 change is physical, not code: get the t530 *inline*
In the testbed, the OVS switch `s1` IS the whole network, so the controller sees everything. On a
real network, devices attach to a Wi-Fi AP + router — the t530 sees nothing unless traffic
physically crosses a switch it controls. Pick a deployment mode:

| Mode | How | Blocking | Best for |
|---|---|---|---|
| **A. Inline bridge / gateway** | t530 with **2 NICs** runs OVS as an L2 bridge between the LAN switch/AP and the router; all traffic transits it | ✅ OpenFlow DROP | whole-network, factory |
| **B. t530 as the Wi-Fi AP** | t530 runs `hostapd` + OVS bridge; phones/cameras/sensors associate directly to it | ✅ OpenFlow DROP, per-device MAC | **"attach any device"**, smart-home |
| C. SPAN/mirror (monitor-only) | managed switch mirrors to the t530 | ❌ (detect only; enforce via switch-ACL/RADIUS) | can't touch the switch |

**Recommendation for your test (phones + any-vendor IoT + cameras + LAN Kali): Mode B** — the t530
becomes the AP everything joins, so it sees every device's real MAC and every packet, and MAC-based
`dl_src` DROP works natively. This is exactly what Mininet-WiFi was emulating (`ap1` + OVS `s1`), so
the controller code needs almost no change — the change is bringing up a real `hostapd` + OVS bridge
and pointing the controller at it (`SNORT_PHYS_IFACE`/`SNORT_IFACES` = the real bridge/uplink).

---

## 1. Code assessment — REMOVE / CHANGE / ADD
All refs are `Controller/Controller_main_Claude.py` unless noted.

### 1a. CHANGE — testbed assumptions that are wrong on a real LAN (must fix)
| What | Where | Problem on a real net | Fix |
|---|---|---|---|
| `_is_external_ip` hardcodes `10.` = internal | `~:1040` | On a `192.168.x` LAN your real devices look "external" → wrongly iptables-blocked instead of OpenFlow-blocked | Make "internal" a **configurable LAN CIDR** (e.g. `192.168.1.0/24`); external = not in it |
| `_ext_whitelist` = testbed IPs | `~:330` | `.200/.201` mean nothing on a real net; your gateway/admin aren't protected | Load whitelist from config: **gateway IP, controller, admin host** |
| `iot_mac_prefixes = ['00:11:22','aa:bb:cc']` | `~:228` | Only 2 fake OUIs — **no real device is recognized as IoT** | Replace with real discovery (§1c) |
| `gateway_mac_prefixes` hardcoded | `~:251` | Won't match a real router | Detect the gateway from the default route / DHCP, or set in config |
| Snort thresholds tuned to the Mininet 2× mirror | `snort3/sdn_ips_local.rules` (500/5s etc.) | Real traffic isn't double-counted; thresholds mis-fire | Recalibrate against real baseline (§Phase 1) |
| Device/label keying on IP | `traffic_capture.py` | Real DHCP IPs churn; a device changing IP looks new | Key identity on **MAC** (blocking already is `dl_src`); treat IP as mutable |

### 1b. REMOVE / DISABLE — testbed-only, not for production
- **The collection/labeling control channel:** `REGISTER:NAME/IOT`, `LABEL_OVERRIDE`, `ATTACK_START/STOP`, `MININET_EVENT`, `CONTROL:ROTATE` (dataset collection). Harmless but dev-only — gate them behind a `--dev` flag or ignore in prod; real devices don't self-register (discovery replaces `REGISTER`).
- **Not deployed at all:** `SDN Topology/topology.py` (testbed + attack generators + background-traffic simulator), `Controller/traffic_capture_diag.py`, `Controller/Controller.py`, `Controller/ryu_ips_app.py`. Keep in the repo, ship only the live set.
- **`dataset.csv` write in production** — you don't need a growing training CSV once deployed; keep it only during the learning phase, then disable/rotate to avoid filling the disk.

### 1c. ADD — what a real deployment needs (new work)
1. **A config file** (`ips_config.yaml`) instead of env vars + hardcodes: `lan_cidr`, `whitelist`, `gateway`, `block_mode` (monitor/guarded/full), `interfaces`, `model_paths`, `protected_macs`. One place the installer edits.
2. **Real device discovery for ANY vendor** (replaces the OUI stub so unknown sensors are identified):
   - **Full IEEE OUI lookup** (bundle the OUI DB) instead of a 2-entry list.
   - **DHCP fingerprinting** (options 55/60/12) and **mDNS/SSDP/UPnP** passive listening → device type + name for phones/cameras/sensors of any brand.
   - Fall back to "unknown device, profiled by behavior" — the AE handles unknown vendors *by traffic shape*, which is the project's strength; lean on it.
3. **A mandatory learning phase + retrain** (the biggest real-world requirement): the AE + RF are trained on Mininet traffic; real phone/camera/sensor traffic looks nothing like it → false positives. Run **monitor-only for days**, capture the real normal, then **retrain the AE baseline** (`ml_models/build_ae_bundle.py`) and re-fit thresholds; RF stays as the 6-attack classifier (or retrain if you collect real attacks). Non-negotiable before enabling blocking.
4. **Safe-by-default enforcement:** default `block_mode = monitor` (DETECT:ON + ML:OBSERVE) on first boot; a **`protected_macs` never-block list** (the router, the owner's phone, medical/critical factory devices); graduate to blocking only after the baseline. A wrongly-blocked camera in a home is a support incident — bias to safe.
5. **Ops hardening:** a `systemd` unit (auto-start/restart), **log rotation**, model/version pinning, and **alert forwarding** (email/push/SIEM) off the existing `/ips/alerts` REST endpoint so no one has to watch a terminal.
6. **IP-churn-resilient state + DHCP awareness:** track IP↔MAC leases so blocking/unblocking follows the device across DHCP renewals.
7. **(If any device sits behind an L3 hop)** a non-OpenFlow enforcement fallback (switch ACL / RADIUS CoA) — in flat L2 Wi-Fi (Mode B) MAC-DROP is enough, so this is only for routed segments.

---

## 2. Phased rollout
```
Phase 0  Hardware & inline placement   — t530 as AP+OVS (Mode B) or 2-NIC bridge; config file; devices join
Phase 1  Passive learning (monitor)    — DETECT:ON + ML:OBSERVE for N days; discover devices; capture real normal
Phase 2  Retrain & validate            — retrain AE (+RF) on real normal; prove 0 blocks/flags at rest
Phase 3  Guarded blocking + Kali test  — protect critical MACs; block high-confidence only; attack from Kali
Phase 4  Full autonomous + ops         — enable full-stack blocking, alerting, systemd, log rotation
```

## 3. Execution
**Phase 0 — placement.** Bring up Mode B: `hostapd` on the t530's Wi-Fi radio bridged into OVS;
add the bridge as the controller's data-plane + Snort iface. Join your phone, cameras, and sensors to
the SSID; join Kali to the same LAN. Verify `GET /ips/switches` = 1 and every device's MAC appears
(dashboard / `_ip_to_mac`). Edit `ips_config.yaml`: `lan_cidr` = your real subnet, whitelist = router
+ admin, `block_mode: monitor`.

**Phase 1 — learn.** `CONTROL:DETECT:ON` + `CONTROL:ML:OBSERVE`. Let real life run (people browsing,
cameras streaming, sensors reporting) for **several days**. Confirm the AE flags **normal** as normal
(max conf < 0.60); note every device that trips a tier at rest — those are your FP sources.

**Phase 2 — retrain.** Export the captured normal → retrain the AE bundle
(`build_ae_bundle.py --csv <real-normal> --percentile 99`) and re-deploy. Re-run Phase 1 briefly:
**target 0 flags/blocks at rest.** Tune `CONTROL:ML:AE:BLOCK` up if a noisy device still trips it.

**Phase 3 — guarded blocking + the Kali test.** Add critical devices to `protected_macs`. Set
high-confidence-only blocking. Then run the **red-team campaign** (`red_team_test_runbook.md`) from
Kali against the real phones/cameras/sensors *and* the t530: floods, scans, ARP spoof, low-and-slow.
Fill the `production_readiness_results.md` scorecard — especially **O3 (zero false positives)** now
that traffic is real. This is the honest test of whether it generalizes.

**Phase 4 — go live.** `CONTROL:ML:AUTHORIZE`, enable external auto-block (`IPS_EXTERNAL_BLOCK=1`,
whitelist your admin IP), wire alerting, install the systemd unit + log rotation.

## 4. Risks & guardrails (real network ≠ lab)
- **False positives block a real user's device** → default monitor-only, `protected_macs`, easy
  dashboard unblock, and the mandatory retrain. Weight this above detection rate.
- **Availability:** a single t530 inline is a single point of failure — plan a bypass (fail-open
  relay) for a home, or a standby for a factory.
- **Legal/privacy:** you're now inspecting real people's traffic — only on networks you own/administer,
  with consent; the flow-statistical tiers avoid payload inspection, which helps.
- **Encrypted traffic:** Snort's content rules are blunted by TLS; rate/RF/AE keep working on
  metadata — position the product on behavioral detection, not DPI.

## 5. Minimal code change-list (Phase 0)
1. ✅ **DONE** — `Controller/ips_config.json` + `_load_ips_config()` loader (`lan_cidr`, `ext_whitelist`,
   `protected_macs`). Absent/invalid → testbed-safe defaults.
2. ✅ **DONE** — `_is_external_ip` now uses the configurable `lan_cidr` (default `10.0.0.0/8`) instead
   of `startswith('10.')`. Validated: testbed 10.x=internal preserved; real `192.168.1.0/24` devices
   correctly internal.
3. ✅ **DONE** — `_ext_whitelist` sourced from config (+ `IPS_MGMT_WHITELIST` env, + defaults).
4. ⏳ **PENDING (larger)** — replace `iot_mac_prefixes`/`gateway_mac_prefixes` with OUI-DB +
   DHCP-fingerprint discovery for any-vendor devices.
5. ✅ **DONE** — `protected_macs` never-block list enforced in both `block_attacker` (tier path) and
   `_do_block_attacker` (REST path); logs `[PROTECTED] …` and skips.
6. ◑ **PARTIAL** — startup is already monitor-only (DETECT OFF at boot), so the safe default holds;
   gating REGISTER/LABEL/collection behind `--dev` is deferred (harmless in prod).

**Still to do before blocking on a real net:** item 4 (device discovery) and the **mandatory retrain**
(Phase 2) on the real network's normal traffic — the models are Mininet-trained until then.
