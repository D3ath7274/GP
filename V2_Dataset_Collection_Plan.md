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

## SESSIONS 2–7 — one attack type each (ONE command per session)

Do the global setup, then baseline + detection, then a single
`run_attack_session` call. It runs **8 diverse source→target attacks** (heavy /
light / wired / IoT hosts, with lateral targets), with the **settle built in**, and
a **longer duration for floods** to beat flow-collapse. It blocks the CLI until the
whole session finishes.

```text
mininet-wifi> py net.detect_off(net)                       # instant
mininet-wifi> py net.start_background_traffic(net)         # instant
mininet-wifi> py net.wait(net, 300)                        # BLOCKS 300 s (devices mature)
mininet-wifi> py net.detect_on(net)                        # instant
mininet-wifi> py net.wait(net, 5)                          # BLOCKS 5 s (DAI baseline freeze)
mininet-wifi> py net.run_attack_session(net, '<KIND>')     # BLOCKS the whole session (see table)
```
Then `exit` → `Ctrl-C` → on the Controller VM, rename + validate:

| Session | one command | rename + validate |
|---|---|---|
| 2 ICMP | `py net.run_attack_session(net,'icmp')` | `mv dataset.csv dataset_session2_icmp.csv` · `python3 validate_dataset.py dataset_session2_icmp.csv "ICMP Flood"` |
| 3 SYN | `py net.run_attack_session(net,'syn')` | `mv dataset.csv dataset_session3_syn.csv` · `python3 validate_dataset.py dataset_session3_syn.csv "SYN Flood"` |
| 4 UDP | `py net.run_attack_session(net,'udp')` | `mv dataset.csv dataset_session4_udp.csv` · `python3 validate_dataset.py dataset_session4_udp.csv "UDP Flood"` |
| 5 Port Scan | `py net.run_attack_session(net,'scan')` | `mv dataset.csv dataset_session5_portscan.csv` · `python3 validate_dataset.py dataset_session5_portscan.csv "Port Scan"` |
| 6 ARP | `py net.run_attack_session(net,'arp')` | `mv dataset.csv dataset_session6_arpspoof.csv` · `python3 validate_dataset.py dataset_session6_arpspoof.csv "ARP Spoofing"` |
| 7 CPS | `py net.run_attack_session(net,'cps')` | `mv dataset.csv dataset_session7_cps.csv` · `python3 validate_dataset.py dataset_session7_cps.csv "Control Plane Saturation"` |

**Auto durations:** floods (`icmp`/`syn`/`udp`) run **60 s** × 8 pairs (~10 min) to
generate enough rows despite flow-collapse; `scan`/`cps`/`arp` run **25 s** × 8
pairs (~5 min) since they're already row-heavy.

**If a class is still thin** (validator NOTE `<200`), top it up without redoing the
session — re-run with a longer duration and/or extra round, save as a `_b` file,
and include BOTH files in the merge:
```text
mininet-wifi> py net.run_attack_session(net, 'icmp', duration=90, rounds=2)
```
```bash
mv dataset.csv dataset_session2_icmp_b.csv
python3 validate_dataset.py dataset_session2_icmp_b.csv "ICMP Flood"
```

> Watch the controller log: each attack prints the Snort/DAI alert and
> `ATTACK CONFIRMED <type>`.

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
| `run_attack_session` — 8 attacks (floods 60 s each / scan,cps,arp 25 s each) | ~10 min (flood) / ~5 min (other) |
| stop + rename + validate | ~1 min |
| **per flood session (icmp/syn/udp)** | **~17 min** |
| **per scan/arp/cps session** | **~12 min** |

Whole collection (1 normal + 6 attack) ≈ **1.5–2 hours** (the longer floods buy
the extra rows).

---

## Checklist (per session)

- [ ] Controller started with `IPS_V2_FEATURES=1` (log: "v2 (corrected)")
- [ ] `sudo mn -c` → topology up → IoT registered (log: `IoT registration via UDP`) → `pingall` OK
- [ ] `detect_off` → `start_background_traffic` → `wait 300` (600 for S1)
- [ ] `detect_on` → `wait 5`  (skip for the normal session)
- [ ] `py net.run_attack_session(net,'<kind>')` (one command; blocks till done); log shows `ATTACK CONFIRMED <type>`
- [ ] `exit` → `Ctrl-C` → `mv dataset.csv dataset_sessionN_<type>.csv`
- [ ] `python3 validate_dataset.py dataset_sessionN_<type>.csv "<Type>"` → **PASS**
- [ ] after all 7: `dataset_merge.py` → `validate_dataset.py dataset_v2_master.csv` → **PASS** → retrain
