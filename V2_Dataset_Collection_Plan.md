# V2 Dataset Collection Plan — Per-Session, Corrected Features, Timed Runbook

**Decision: keep the per-session structure** (1 normal session + 6 attack
sessions, one primary attack type each) — unambiguous labels, easy per-class
balancing, auditable, re-runnable. We fix the three things that made the old data
unsuitable:

1. **Corrected features** — capture in v2 mode (`IPS_V2_FEATURES=1`) so the ~13
   dead columns and the bug-artifact `fwd_bwd_*_ratio` become real.
2. **Profile diversity** — launch each attack from **several devices** (heavy,
   light, IoT) with **lateral targets**, so the model sees each attack from many
   normal profiles. (This is the gap that broke v1.)
3. **Clean labels** — the controller now ignores Snort's generic signatures and
   only labels with the six canonical classes.

Same 102-column schema, same pipeline architecture. Keep **ML mode OFF** during
collection (default) — detection ON only *labels*, it does not block.

---

## ⏱ Timing rule (read this first)

**`py net.launch_attack(...)` is BLOCKING and self-timed.** Each call:
`ATTACK_START` → runs the tool **25 s** → `ATTACK_STOP` → **15 s settle**, and
only returns when it is ready for the next one.

> **How long do you wait between attacks? 0 seconds of manual waiting.** The 15 s
> settle is *inside* the call. Paste the six calls one after another; each blocks
> ~40 s, so a session's attacks take ~4 min total. Every command below is
> annotated with how long it blocks.

`py net.wait(net, N)` simply blocks the CLI for `N` seconds (baseline maturation).

**What the annotations mean:** `# ~40s` / `# BLOCKS 300 s` = the command *occupies
the CLI for that long*. After you press Enter, the `mininet-wifi>` prompt will not
come back until it finishes — that IS the wait. Do not add any wait on top; just
enter the next command when the prompt reappears.

---

## Global setup (every session)

On the **Controller VM** (fresh `dataset.csv` each session):
```bash
cd <repo>/Controller
IPS_V2_FEATURES=1 ryu-manager Controller.py        # log MUST say: Feature schema mode: v2 (corrected)
```

> **The controller now auto-rotates any existing `dataset.csv` aside on startup**
> (to `dataset.csv.bak-<timestamp>`) so each run writes a fresh, correct-schema
> file — this prevents the append-corruption that happens when a run writes into a
> leftover/old-schema `dataset.csv`. The log prints `… rotated to …` when it does.
> Periodically clean the `*.bak-*` files. (If you ever see a capture validate with
> `cols=50` and float values in `attack_type`, that's stale-append corruption —
> delete the file and re-run.)
On the **Topology VM**:
```bash
sudo mn -c                 # ~5 s  — clean stale state
sudo python3 topology.py   # ~15 s — wait for the mininet-wifi> prompt
```
In the Mininet CLI:
```text
mininet-wifi> py net.register_iot_device(net, 'TempSensor', '10.0.0.5/24', '00:00:00:00:00:05', 's1', 'IOT:TempSensor')   # instant
mininet-wifi> py net.register_iot_device(net, 'Cam', '10.0.0.6/24', '00:00:00:00:00:06', 's1', 'IOT:Camera')              # instant
mininet-wifi> nodes        # expect sta1 sta2 h1 h2 TempSensor Cam
mininet-wifi> pingall      # ~10 s
```
> Prereqs once: `curl` on the Topology VM; `CONTROLLER_IP` correct; TCP 6633 +
> UDP 9999 open. Confirm the controller log shows `IoT registration via UDP` for
> both devices.

---

## SESSION 1 — Normal only (rich, diverse baseline)

```text
mininet-wifi> py net.detect_off(net)                       # instant
mininet-wifi> py net.start_background_traffic(net)         # instant (starts loops)
mininet-wifi> py net.wait(net, 600)                        # BLOCKS 600 s (10 min of pure normal)
```
Then `exit` (CLI), `Ctrl-C` (controller). On the Controller VM:
```bash
mv dataset.csv dataset_session1_normal.csv
python3 validate_dataset.py dataset_session1_normal.csv     # expect PASS (v2 features live; only 'normal')
```

---

## SESSIONS 2–7 — one attack type each (same recipe)

Do the global setup, then the baseline + detection, then the six attacks
back-to-back (no manual wait — each blocks ~40 s):

```text
mininet-wifi> py net.detect_off(net)                       # instant
mininet-wifi> py net.start_background_traffic(net)         # instant
mininet-wifi> py net.wait(net, 300)                        # BLOCKS 300 s (all devices mature: >=180s + >=20 flows)
mininet-wifi> py net.detect_on(net)                        # instant
mininet-wifi> py net.wait(net, 5)                          # BLOCKS 5 s (let DAI baseline freeze)
```

### Session 2 — ICMP Flood
```text
mininet-wifi> py net.launch_attack(net, 'sta1', 'icmp', '10.0.0.4')        # ~40s (blocks)
mininet-wifi> py net.launch_attack(net, 'Cam',  'icmp', '10.0.0.4')        # ~40s (infected IoT)
mininet-wifi> py net.launch_attack(net, 'TempSensor', 'icmp', '10.0.0.3')  # ~40s (lateral)
mininet-wifi> py net.launch_attack(net, 'h1',   'icmp', '10.0.0.4')        # ~40s
mininet-wifi> py net.launch_attack(net, 'sta2', 'icmp', '10.0.0.6')        # ~40s (lateral to IoT)
mininet-wifi> py net.launch_attack(net, 'sta1', 'icmp', '10.0.0.4')        # ~40s
```
`exit` → `Ctrl-C` → on the Controller VM:
```bash
mv dataset.csv dataset_session2_icmp.csv
python3 validate_dataset.py dataset_session2_icmp.csv "ICMP Flood"          # must print PASS
```

### Session 3 — SYN Flood
```text
mininet-wifi> py net.launch_attack(net, 'sta1', 'syn', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'Cam',  'syn', '10.0.0.4')         # ~40s (infected IoT)
mininet-wifi> py net.launch_attack(net, 'TempSensor', 'syn', '10.0.0.3')   # ~40s (lateral)
mininet-wifi> py net.launch_attack(net, 'h1',   'syn', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta2', 'syn', '10.0.0.6')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta1', 'syn', '10.0.0.4')         # ~40s
```
```bash
mv dataset.csv dataset_session3_syn.csv
python3 validate_dataset.py dataset_session3_syn.csv "SYN Flood"
```

### Session 4 — UDP Flood
```text
mininet-wifi> py net.launch_attack(net, 'sta1', 'udp', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'Cam',  'udp', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'TempSensor', 'udp', '10.0.0.3')   # ~40s (lateral)
mininet-wifi> py net.launch_attack(net, 'h1',   'udp', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta2', 'udp', '10.0.0.6')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta1', 'udp', '10.0.0.4')         # ~40s
```
```bash
mv dataset.csv dataset_session4_udp.csv
python3 validate_dataset.py dataset_session4_udp.csv "UDP Flood"
```

### Session 5 — Port Scan
```text
mininet-wifi> py net.launch_attack(net, 'sta1', 'scan', '10.0.0.4')        # ~40s
mininet-wifi> py net.launch_attack(net, 'Cam',  'scan', '10.0.0.3')        # ~40s (infected IoT scans peer)
mininet-wifi> py net.launch_attack(net, 'TempSensor', 'scan', '10.0.0.4')  # ~40s
mininet-wifi> py net.launch_attack(net, 'h1',   'scan', '10.0.0.6')        # ~40s (lateral to IoT)
mininet-wifi> py net.launch_attack(net, 'sta2', 'scan', '10.0.0.4')        # ~40s
mininet-wifi> py net.launch_attack(net, 'sta1', 'scan', '10.0.0.3')        # ~40s
```
```bash
mv dataset.csv dataset_session5_portscan.csv
python3 validate_dataset.py dataset_session5_portscan.csv "Port Scan"
```

### Session 6 — ARP Spoofing
```text
mininet-wifi> py net.launch_attack(net, 'sta1', 'arp', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'Cam',  'arp', '10.0.0.4')         # ~40s (infected IoT)
mininet-wifi> py net.launch_attack(net, 'TempSensor', 'arp', '10.0.0.4')   # ~40s
mininet-wifi> py net.launch_attack(net, 'h1',   'arp', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta2', 'arp', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta1', 'arp', '10.0.0.4')         # ~40s
```
```bash
mv dataset.csv dataset_session6_arpspoof.csv
python3 validate_dataset.py dataset_session6_arpspoof.csv "ARP Spoofing"
```

### Session 7 — Control Plane Saturation
```text
mininet-wifi> py net.launch_attack(net, 'sta1', 'cps', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'Cam',  'cps', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'TempSensor', 'cps', '10.0.0.3')   # ~40s (lateral)
mininet-wifi> py net.launch_attack(net, 'h1',   'cps', '10.0.0.4')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta2', 'cps', '10.0.0.6')         # ~40s
mininet-wifi> py net.launch_attack(net, 'sta1', 'cps', '10.0.0.4')         # ~40s
```
```bash
mv dataset.csv dataset_session7_cps.csv
python3 validate_dataset.py dataset_session7_cps.csv "Control Plane Saturation"
```

> Watch the controller log: each attack should print the Snort/DAI alert and
> `ATTACK CONFIRMED <type>`. If `validate_dataset.py` reports the class is thin
> (<200 rows) or from <2 sources, re-run that one session before merging.

---

## Per-session validation — what PASS means

`validate_dataset.py <file> "<Type>"` must end with **PASS ✅**. It checks:

- **v2 mode was on** — `reply_rate` and `bwd_packet_count` are not both all-zero
  (if they are, you captured in v1 mode → re-capture with `IPS_V2_FEATURES=1`).
- **labels are canonical** — no `SNMP trap`/`BAD-TRAFFIC`/`MISC` leakage.
- **enough attack rows** — ≥50 (hard) / ≥200 (recommended) for the session type.
- **profile diversity** — the attack appears from ≥2 source IPs.
- **IoT flags** — `is_registered_iot=1` on `10.0.0.5`/`10.0.0.6` rows.
- **no NaN/inf**.

Fix and re-collect any session that does not PASS *before* merging.

---

## Merge + final validation

From `Controller/`, once all 7 sessions PASS:
```bash
python3 dataset_merge.py \
  dataset_session1_normal.csv dataset_session2_icmp.csv dataset_session3_syn.csv \
  dataset_session4_udp.csv dataset_session5_portscan.csv dataset_session6_arpspoof.csv \
  dataset_session7_cps.csv --output dataset_v2_master.csv
```
`dataset_merge.py` enforces identical schema across sessions (crashes on
mismatch), reports per-class counts (watch for ⚠ LOW), and writes
`dataset_v2_master.csv` (audit, with meta) + `dataset_v2_master_training.csv`
(meta stripped).

**Final validation of the merged master:**
```bash
python3 validate_dataset.py dataset_v2_master.csv        # expect PASS; review the printed report
```
Confirm in the report:
- all **6 canonical attack types present**, each from **multiple source IPs**
  (including the IoT hosts for the infected-device story);
- per-class counts reasonable (aim ≥200/class; the merge report flags lows);
- `is_registered_iot=1` present on IoT rows;
- v2 features live; no NaN/inf; only canonical labels.

Then proceed to **Pipeline Retrain.md**.

---

## Timing summary

| Step | Time |
|---|---|
| setup (`mn -c` + topology + register + pingall) | ~1–2 min |
| baseline maturation (`wait 300`; 600 for S1) | 5 min (10 for S1) |
| 6 attacks (`launch_attack` ×6, ~40 s each, back-to-back) | ~4 min |
| stop + rename + validate | ~1 min |
| **per attack session** | **~11–12 min** |

Whole collection (1 normal + 6 attack) ≈ **80–90 minutes**.

---

## Checklist (per session)

- [ ] Controller started with `IPS_V2_FEATURES=1` (log: "v2 (corrected)")
- [ ] `sudo mn -c` → topology up → IoT registered (log: `IoT registration via UDP`) → `pingall` OK
- [ ] `detect_off` → `start_background_traffic` → `wait 300` (600 for S1)
- [ ] `detect_on` → `wait 5`  (skip for the normal session)
- [ ] 6 `launch_attack` calls back-to-back (no manual wait); log shows `ATTACK CONFIRMED <type>` each
- [ ] `exit` → `Ctrl-C` → `mv dataset.csv dataset_sessionN_<type>.csv`
- [ ] `python3 validate_dataset.py dataset_sessionN_<type>.csv "<Type>"` → **PASS**
- [ ] after all 7: `dataset_merge.py` → `validate_dataset.py dataset_v2_master.csv` → **PASS** → retrain
