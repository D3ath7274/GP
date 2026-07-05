# 90-Second Demo Video — Runbook & Shot List

Goal: prove the system is **operational** — it detects, names, and **blocks** known
attacks, catches a **zero-day** with the Autoencoder, and defends against an **outside**
attacker — all live, in 90 seconds. An **optional extended segment** adds the adaptive
SD-WAN traffic-steering (QoS) capability for a ~2-minute cut. Legend: **[t530]** controller ·
**[mn]** Mininet CLI · **[dash]** browser dashboard · **[kali]** external attacker.

---

## Pre-flight (do this BEFORE you hit record — keep it off-camera)

1. **[t530]** Controller running (fresh log), armed full-stack:
   ```bash
   # launch with external-attacker defence on (Part 5):
   sudo IPS_EXTERNAL_BLOCK=1 SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=enp1s0,snort_tap IPS_V2_FEATURES=1 \
     python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
     Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
   python3 ipsctl.py CONTROL:DETECT:ON
   python3 ipsctl.py CONTROL:ML:AUTHORIZE:0.80
   ```
2. **[mn]** Topology up, hosts registered, background traffic running, `pingall` clean.
3. **[dash]** `http://<t530>:8081/` open, zoomed ~125%, showing the idle (green) state.
4. Arrange the screen: **dashboard on the left**, **controller log on the right** (both visible).
5. Confirm reset: `python3 ipsctl.py CONTROL:CLEAR` and no hosts in the blocked table.
6. **Dashboard smoke test (do this once, off-camera).** The blocked table only renders if you're on
   the commit with the `Infinity`→finite `until` fix — older code returns invalid JSON and the table
   stays empty *even though blocks work*. Verify:
   ```bash
   curl -s -X POST http://127.0.0.1:8081/ips/block -H 'Content-Type: application/json' -d '{"src_ip":"10.0.0.9","reason":"smoke"}'
   curl -s http://127.0.0.1:8081/ips/blocked        # must be valid JSON listing 10.0.0.9 (no "Infinity")
   python3 ipsctl.py CONTROL:UNBLOCK:10.0.0.9
   ```
   If `/ips/blocked` shows `Infinity` or the dashboard table won't populate, `git pull` + restart.

> Rehearse once. Between takes, reset with `CONTROL:UNBLOCK:<ip>` for every blocked host
> (blocks are **permanent**) + `CONTROL:CLEAR`, and clear the browser event timeline (reload).

---

## The 90-second shot list

| Time | On screen | Command / action | Say (voiceover) |
|---|---|---|---|
| **0:00–0:08** | Title card → the dashboard idle + controller banner | — | "An adaptive, four-tier intrusion prevention system for IoT on a software-defined network — running live on an HP t530 thin client." |
| **0:08–0:16** | Point at the four tier tiles (Snort/rate/RF/AE all lit "loaded"), threat level green | — | "Signatures, rate analysis, a Random Forest, and an Autoencoder — all loaded and watching." |
| **0:16–0:32** | Run a **SYN flood**; controller prints `IDS ALERT` then the `🚫 ATTACKER BLOCKED` box; dashboard threat level jumps, attacker appears in the blocked table | **[mn]** `sta1 hping3 -S --flood -p 80 10.0.0.4` | "A SYN flood from an internal host is detected and blocked in under a fifth of a second — the attacker is now in the blocked table." |
| **0:32–0:48** | **Surgical proof** — split view: attacker gets 100% loss, an innocent host is unaffected | **[mn]** `sta1 ping -c4 10.0.0.4` (100% loss) then `sta2 ping -c4 10.0.0.4` (0% loss) | "The attacker is quarantined — total packet loss — while a legitimate host on the same switch keeps full connectivity. Surgical, not a blackout." |
| **0:48–1:04** | **Zero-day** — stop SYN, launch an attack the models were never trained on; controller prints `[AE] ANOMALY (block)` labelled `Anomaly (AE)` | **[mn]** run the held-out/unseen attack at `10.0.0.4` | "This attack type was never in training. The Autoencoder flags it purely as *not-normal* and blocks it — real zero-day defence." |
| **1:04–1:22** | **Outside attacker** — Kali port-scans the controller's own IP; controller prints `[EXT-BLOCK] host-firewall DROP …`; re-run scan shows filtered/blocked | **[kali]** `nmap -sS -p 1-1000 <t530-ip>` then re-run to show it's dropped | "An external Kali box scans the controller itself — the SDN can't see that, so Snort detects it and drops it at the host firewall." |
| **1:22–1:30** | Back to the full dashboard: blocked table populated, timeline scrolling, health panel nominal | — | "Known attacks, zero-days, and outside threats — detected, named, and blocked in real time, on edge hardware." |

---

## Attack command reference (internal, [mn] — swap any into a beat)

| Attack | Command (attacker = sta1, target = h2 10.0.0.4) |
|---|---|
| ICMP flood | `sta1 hping3 --icmp --flood 10.0.0.4` |
| SYN flood | `sta1 hping3 -S --flood -p 80 10.0.0.4` |
| UDP flood | `sta1 hping3 --udp --flood -p 53 10.0.0.4` |
| Control-Plane Saturation | `sta1 hping3 --udp --flood -p ++1 10.0.0.4` |
| **Port scan** | `sta1 nmap -sS -p 1-1000 10.0.0.4` |
| **ARP spoofing** | `sta1 arpspoof -i sta1-wlan0 -t 10.0.0.4 10.0.0.3 &` |

**Port scan** → Snort `port_scan` inspector (GID 122) + the rate tier (`>100` distinct dst
ports) → blocked as `Port Scan` under DETECT:ON. On screen: the `IDS ALERT … Port Scan` +
the `🚫 ATTACKER BLOCKED` box.

**ARP spoofing** → sta1 forges the IP→MAC binding for `10.0.0.3` toward the victim
`10.0.0.4`; the controller prints the `⚠ ARP SPOOFING DETECTED (DAI)` box (attacker MAC vs
real owner). Notes:
- The interface is the **attacker's own** iface: `sta1-wlan0` for a Wi-Fi station,
  `h1-eth0` for a wired host — adjust to whichever host you attack from.
- `arpspoof` runs continuously; it's backgrounded with `&`. Stop it before the next take:
  `mn> sta1 pkill arpspoof` (and re-establish bindings with `pingall`).
- **Current build:** DAI *detects and flags* the spoofer (the box) but does **not**
  auto-block it — narrate this beat as "detected and flagged," not "blocked." (Say the
  word if you want DAI wired to auto-block under DETECT:ON like Snort/rate.)

**External (Kali) port scan** of the controller host itself: `nmap -sS -p 1-1000 <t530-ip>`
→ Snort on the physical NIC → `[EXT-BLOCK] host-firewall DROP` (needs `IPS_EXTERNAL_BLOCK=1`).

---

## Optional extended segment — Adaptive traffic steering (QoS, ~30 s)
Shows the "adaptive SD-WAN" claim beyond security: the controller steers **priority** traffic onto
a fast path and best-effort traffic onto a backup path. **This is a *separate* controller +
topology** (OpenFlow 1.3, 4-switch) from the IPS above, so record it as its **own segment** and cut
it in — don't try to run it in the same live session as the IPS topology.

**Setup (off-camera):**
```bash
# controller host:  cd QoS && ryu-manager smart_controller.py     # OF 1.3, port 6653, reads ./config.json
# Mininet VM:       set CONTROLLER_IP in QoS/smart_topology.py, then: sudo python3 QoS/smart_topology.py
```
**Shot (~30 s):** frame the `smart_controller.py` log.
| On screen | Command ([mn]) | Say |
|---|---|---|
| Log prints `>>> [FAST PATH - VIP]` | `sta1 iperf -c 10.0.0.3 -p 1883` (IoT/MQTT port) | "Priority IoT traffic is steered onto the fast, low-latency path." |
| Log prints `>>> [BACKUP PATH]` | `sta1 iperf -c 10.0.0.3 -p 8080` (best-effort port) | "Ordinary traffic takes the backup path — the controller adapts the route to the application." |

Narrate by **application priority** (IoT vs best-effort), not raw Mbps — the data-rate threshold is
policy-driven, not yet measured live (see `QoS/README.md`). Every s1 flow is also mirrored to the
IPS, so steering and inspection run together.

## Cuts
- **90-second core:** the shot-list beats as written (block → surgical → zero-day → outsider → wrap).
- **~2-minute extended cut:** insert the **QoS traffic-steering** segment right before the wrap
  (after the outsider beat), and end on a wrap that also says "…and steers traffic by policy."
- **If you only have time for 3 beats:** keep **0:16–0:32 (block)**, **0:32–0:48 (surgical)**, and
  **0:48–1:04 (zero-day)** — detection, enforcement, and the headline zero-day claim. The outsider
  beat is the strongest "wow" if the Kali box is ready; drop it first if a take runs long.

## Fallback if a live attack misbehaves on camera
Pre-record each attack segment separately, then cut together — every beat above is
independent and each produces its own on-screen block box, so takes compose cleanly.

## Reset checklist between takes
```bash
python3 ipsctl.py CONTROL:UNBLOCK:10.0.0.1        # repeat for each blocked internal IP
python3 ipsctl.py CONTROL:UNBLOCK:<kali-ip>       # also removes the host-firewall rule
python3 ipsctl.py CONTROL:CLEAR
# reload the dashboard to clear the event timeline
```
