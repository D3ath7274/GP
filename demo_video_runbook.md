# 90-Second Demo Video — Runbook & Shot List

Goal: prove the system is **operational** — it detects, names, and **blocks** known
attacks, catches a **zero-day** with the Autoencoder, and defends against an **outside**
attacker — all live, in 90 seconds. Legend: **[t530]** controller · **[mn]** Mininet CLI ·
**[dash]** browser dashboard · **[kali]** external attacker.

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
| **1:04–1:22** | **Outside attacker** — Kali port-scans the controller's own IP; controller prints `[EXT-BLOCK] host-firewall DROP …`; re-run scan shows filtered/blocked | **[kali]** `nmap -sS <t530-ip>` then re-run to show it's dropped | "An external Kali box scans the controller itself — the SDN can't see that, so Snort detects it and drops it at the host firewall." |
| **1:22–1:30** | Back to the full dashboard: blocked table populated, timeline scrolling, health panel nominal | — | "Known attacks, zero-days, and outside threats — detected, named, and blocked in real time, on edge hardware." |

---

## If you only have time for 3 beats
Keep **0:16–0:32 (block)**, **0:32–0:48 (surgical)**, and **0:48–1:04 (zero-day)** — those
three prove detection, enforcement, and the headline zero-day claim. The outsider beat
(1:04) is the strongest "wow" if the Kali box is ready; drop it first if a take runs long.

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
