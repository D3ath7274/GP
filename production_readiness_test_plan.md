# Production-Readiness Evaluation Plan — proving the IPS is deployable for a real company

**Framing.** This is the evaluation a startup/company would run as a **proof-of-concept (POC)**
before trusting an IPS in production. It goes beyond "does it block attacks" to the questions that
actually decide adoption: *does it ever block our real users? does it keep up on our hardware? can a
real attacker bypass it? can our one ops person operate it?*

**Authorization.** Everything runs in your own isolated lab (t530 controller + Mininet VM + a Kali
box you own). Only the testbed assets below are targeted. This is defensive validation of your own
system.

**Relationship to other docs.** `red_team_test_runbook.md` = the per-tier attack mechanics (this plan
*calls* it in Phase 2). `t530_full_system_runbook.md` = how to run the system. This plan is the
higher-level **campaign + KPIs + report** that ties them into a "would a company buy this" verdict.

---

## Model the Mininet network as a small company ("Acme IoT Ltd.")
Give the dummy devices business roles so results read like a real deployment:

| Node | IP | Plays (business role) | Traffic profile |
|---|---|---|---|
| `h2` | 10.0.0.4 | **Company web/app server** (the crown jewel) | HTTP + iperf sink |
| `sta1`, `sta2` | 10.0.0.1/.2 | **Employee laptops** (Wi-Fi) | web browsing |
| `h1` | 10.0.0.3 | **Internal file/DB host** | mixed TCP |
| `TempSensor` | 10.0.0.5 | **IoT sensor fleet** | periodic MQTT/HTTP telemetry |
| `Cam` | 10.0.0.6 | **IP camera** | video-style iperf bursts |
| Kali box | 192.168.1.x | **The attacker** (insider foothold *or* outsider) | attack tools |

"Insider" = Kali attacks *through* an exposed service (`net.expose_service`) so it transits the SDN;
"outsider" = Kali hits the controller host's NIC directly.

---

## 1. Objectives (with measurable pass targets)
A company signs off only if these are met — each has a number, not a vibe:

| # | Objective | Metric | Pass target |
|---|---|---|---|
| O1 | **Detect known attacks** | recall per class (6 attacks) | 100% detected, ≥1 tier each |
| O2 | **Detect the unknown** | zero-day (held-out class) caught by AE | flagged + blocked |
| O3 | **Do NOT block legitimate users** | false-positive blocks during heavy legit load | **0** legit hosts blocked (the make-or-break KPI) |
| O4 | **Real-time mitigation** | detection→block latency (BLOCK-box `Latency`) | < 1 s (aim < 250 ms) |
| O5 | **Surgical enforcement** | innocent-host connectivity while attacker blocked | attacker 100% loss, innocent 0% loss |
| O6 | **Runs on edge hardware** | t530 CPU/RAM/disk under sustained flood (`/ips/metrics`) | window compute < 5 s; RAM headroom; no swap-death |
| O7 | **Survives the attack** | controller stays up + responsive under flood | REST/dashboard answer throughout; no hang/crash |
| O8 | **Resists evasion** | low-and-slow, spoofing, randomized ports | each caught by *some* tier, or logged as a known gap |
| O9 | **Operable by one person** | operator can triage + block + unblock + recover via dashboard/`ipsctl` | full loop < 2 min, no code needed |

O3 and O7 are the ones that kill real deployments — weight them heavily.

---

## 2. Phases
```
Phase 0  Lab build & baseline         (1 session)  — network up, roles assigned, baseline captured
Phase 1  Functional detection         → O1, O2     — every attack caught, per tier
Phase 2  Business-continuity / FP      → O3, O5     — heavy legit traffic; nothing legit gets blocked
Phase 3  Performance & scale           → O4, O6, O7 — latency, resource, throughput ceiling, resilience
Phase 4  Adversarial / evasion (Kali)  → O8         — attacker mindset, insider + outsider, evasion tricks
Phase 5  Operational drill (blue team) → O9         — an operator responds to a live incident
Phase 6  Report & verdict             — the KPI scorecard a company/investor reads
```

---

## 3. Execution

### Phase 0 — Lab build & baseline
1. Bring up controller + topology per `t530_full_system_runbook.md` PARTs 2–3; register the IoT
   devices; start background traffic; confirm GATEs (`/ips/switches`=1, `dataset.csv` growing).
2. Arm full stack: `CONTROL:DETECT:ON` + `CONTROL:ML:AUTHORIZE:0.80`.
3. **Whitelist discipline:** launch with `IPS_EXTERNAL_BLOCK=1 IPS_MGMT_WHITELIST=<your-admin-ip>`
   so you don't lock yourself out; the Kali IP must NOT be whitelisted.
4. **Baseline (critical for O3):** let legitimate traffic run **10 min** with NO attack. Record:
   `curl -s :8081/ips/blocked` must stay **empty**, and note the AE's max normal confidence. If a
   legit host gets flagged/blocked at rest, fix that (raise `CONTROL:ML:AE:BLOCK`) before proceeding —
   a product that blocks idle users is dead on arrival.

### Phase 1 — Functional detection (O1, O2)
Run `red_team_test_runbook.md` §5–§6 end to end (each tier isolated, then full stack) against `h2`.
Record per attack: which tier fired (`reason=`), detected Y/N, latency. Zero-day (O2): hold one class
out of training, attack with it, confirm `[AE] ANOMALY (block)`.

### Phase 2 — Business-continuity / false positives (O3, O5) — the differentiator
This is the phase most student projects skip and every company demands.
1. Drive **heavy legitimate load** concurrently (not just idle background):
   ```
   [mn] h2 iperf -s &                    ; sta1 iperf -c 10.0.0.4 -t 120      # big legit transfer
   [mn] Cam iperf -c 10.0.0.4 -u -b 20M -t 120                                # camera video burst
   [mn] for i in $(seq 1 50); do sta2 curl -s 10.0.0.4 & done                 # web bursts
   ```
2. **While that runs**, launch ONE real attack from Kali/`sta1` at `h2`.
3. **Verify O3 + O5:** only the attacker appears in `/ips/blocked`; every legit host still completes
   its transfer/curl. Log any legit host that gets blocked as a **false positive** with the tier +
   confidence that caused it (tune `AE:BLOCK`/`ML:BLOCK` and re-run). Target: **0 FPs.**

### Phase 3 — Performance & scale (O4, O6, O7)
1. **Latency (O4):** run 10 attacks; `grep Latency redteam_run.log` → min/max/mean.
2. **Resource (O6):** sample `curl -s :8081/ips/metrics` at idle, then during a sustained multi-source
   flood; record cpu/ram/disk + `CONTROL:ML:STATS` per-window compute (must stay < 5000 ms).
3. **Throughput ceiling:** ramp flood intensity until window compute approaches the 5 s budget; note
   the packets/s where it saturates — that's your honest scale limit for the writeup.
4. **Resilience (O7):** during the worst flood, confirm the dashboard still loads and `ipsctl`
   commands still take effect (the controller never hangs). This validates the eventlet-hub safety work.

### Phase 4 — Adversarial / evasion, Kali (O8)
Attacker mindset — *try to beat it* (from `red_team_test_runbook.md` §7–§8):
- **Insider through the SDN:** `py net.expose_service(net)` then Kali SYN-flood/scan `<vm-ip>:8080` →
  must block with the **real external IP**, all 4 tiers.
- **Outsider on the controller NIC:** Kali `nmap -sS <t530-ip>` → `[EXT-BLOCK]` iptables DROP.
- **Evasion set:** low-and-slow (`hping3 -i u10000`), randomized source ports (`--rand-source`),
  slow-HTTP, MAC/IP spoofing. For each: *evaded? which tier caught it? how fast?* Gaps here are honest
  Chapter-5 limitations, not failures.

### Phase 5 — Operational drill (O9) — blue team
Simulate the on-call engineer. Someone else launches a surprise attack; **you**, using only the
dashboard + `ipsctl`:
1. Notice the threat-level rise + blocked-table entry.
2. Identify attacker IP/MAC/tier/attack-type from the dashboard.
3. Confirm containment (attacker 100% loss) and business continuity (legit host fine).
4. Do a **false-positive recovery drill:** deliberately over-block, then `CONTROL:UNBLOCK:<ip>` and
   confirm the host returns — proves an operator can reverse a mistake fast. Time the whole loop.

### Phase 6 — Report & verdict
Fill the KPI scorecard (below) with real numbers + evidence (BLOCK boxes, `/ips/metrics` JSON,
`dump-flows`, dashboard screenshots, latency table). The verdict a company reads:
> "Detected N/N attack classes incl. a zero-day, with **0** false positives under heavy load, mean
> block latency X ms, on an 8 GB thin client that stayed responsive throughout."

---

## KPI scorecard (the deliverable)
| KPI | Target | Measured | Evidence | Pass? |
|---|---|---|---|---|
| Known-attack recall (6) | 100% | | Phase 1 table | |
| Zero-day caught | yes | | `[AE] ANOMALY` box | |
| **False positives under load** | **0** | | Phase 2 `/ips/blocked` | |
| Block latency (mean/max) | < 1 s | | `grep Latency` | |
| Surgical (attacker loss / innocent loss) | 100% / 0% | | ping outputs | |
| Window compute under flood | < 5000 ms | | `ML:STATS` | |
| CPU / RAM / disk peak | headroom | | `/ips/metrics` | |
| Throughput ceiling | (record) | | Phase 3 | |
| Controller stayed responsive | yes | | dashboard/ipsctl during flood | |
| Evasion caught / gaps | (record) | | Phase 4 table | |
| Operator response-loop time | < 2 min | | Phase 5 timing | |

---

## From lab to a real company (what changes)
The detection/enforcement logic is transport-agnostic, so the honest gaps to close for a real
deployment (also your Chapter-5 future work):
- **Physical inline placement:** the controller-managed switch must sit inline on real traffic
  (a mirror/SPAN for detection-only, or inline for blocking) — not an emulated OVS.
- **Retrain on the client's normal traffic:** the AE baseline + RF are testbed-trained; a real
  network needs a fresh normal-traffic capture and a retrain (`retrain_rf_v4.py` / `build_ae_bundle.py`).
- **Scale via sampling:** mirroring every packet won't survive core-link rates — sFlow/NetFlow
  sampling beyond the edge/branch volumes this targets.
- **HA + logging:** a single controller is a single point of failure; production needs a standby and
  a SIEM feed off the REST API (`/ips/alerts`).
- **Encrypted traffic:** the signature tier is blunted by TLS; the flow-statistical tiers (rate/RF/AE)
  keep working on metadata — position the product accordingly.
