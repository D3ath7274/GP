# Production-Readiness Evaluation — Results Sheet (fill in as you go)

Companion to `production_readiness_test_plan.md`. Paste real measurements into the blanks (`___`)
as you run each phase. Mark each row **PASS / FAIL / PARTIAL**.

## Test metadata
| Field | Value |
|---|---|
| Date / time | ___ |
| Tester(s) | ___ |
| Git commit (controller) | ___ |
| t530 IP | ___ · Mininet VM IP: ___ · Kali IP: ___ |
| Launch flags | `IPS_EXTERNAL_BLOCK=` ___ · `IPS_MGMT_WHITELIST=` ___ · `IPS_BLOCK_SECONDS=` ___ |
| Models | RF: ___ (v2/v4) · AE threshold: ___ |
| Modes at test | DETECT: ___ · ML: ___ |

---

## KPI SCORECARD (the headline deliverable)
| KPI | Target | Measured | Evidence file/ref | PASS? |
|---|---|---|---|---|
| Known-attack recall (6 classes) | 100% | ___ / 6 | Phase 1 table | ___ |
| Zero-day caught | yes | ___ | `[AE] ANOMALY` box | ___ |
| **False positives under load** | **0** | ___ | Phase 2 log | ___ |
| Block latency — mean / max | < 1 s (aim < 250 ms) | ___ / ___ ms | Phase 3.1 | ___ |
| Surgical — attacker loss / innocent loss | 100% / 0% | ___% / ___% | Phase 2 ping | ___ |
| Window compute under flood | < 5000 ms | ___ ms | `ML:STATS` | ___ |
| CPU / RAM / disk peak | headroom (no swap) | ___% / ___% / ___% | `/ips/metrics` | ___ |
| Throughput ceiling | (record) | ___ pps | Phase 3.3 | ___ |
| Controller stayed responsive | yes | ___ | Phase 3.4 | ___ |
| Evasion caught vs gaps | (record) | ___ / ___ | Phase 4 table | ___ |
| Operator response-loop time | < 2 min | ___ s | Phase 5 | ___ |

**Overall verdict:** ☐ Production-ready  ☐ Ready with caveats  ☐ Not yet — top blockers: ___

---

## Phase 0 — Baseline (idle, 10 min, no attack)
| Check | Expected | Observed | PASS? |
|---|---|---|---|
| `/ips/switches` count | 1 | ___ | ___ |
| `dataset.csv` growing | yes | ___ | ___ |
| Blocked table at idle | empty | ___ | ___ |
| AE max normal confidence | < 0.60 | ___ | ___ |
| Any legit host flagged at rest? | no | ___ | ___ |

## Phase 1 — Functional detection (O1, O2)
| Attack | Isolated tier tested | Detected? | Deciding `reason=` | Blocked (dump-flows)? | Latency (ms) | Notes |
|---|---|---|---|---|---|---|
| ICMP flood | Snort (short) | ___ | ___ | ___ | ___ | ___ |
| SYN flood | Snort (short) | ___ | ___ | ___ | ___ | ___ |
| UDP flood | Snort / rate | ___ | ___ | ___ | ___ | ___ |
| Control-Plane Sat. | Snort / rate | ___ | ___ | ___ | ___ | ___ |
| Port Scan | Snort port_scan | ___ | ___ | ___ | ___ | ___ |
| ARP spoof | DAI (detect) | ___ | DAI box | n/a (detect-only) | ___ | ___ |
| RF isolated (SYN) | Tier 3 | ___ | `ml-___` | ___ | ___ | ___ |
| AE zero-day (held-out) | Tier 4 | ___ | `ae-___` | ___ | ___ | ___ |
| **Recall** | | **___ / 8** | | | | |

## Phase 2 — Business continuity / false positives (O3, O5) — the make-or-break phase
Heavy legit load running (iperf + camera burst + web) while ONE attack fires.
| Legit host / flow | Completed OK? | Blocked? (FP) | Tier+conf if FP | Notes |
|---|---|---|---|---|
| sta1 iperf → h2 (120 s) | ___ | ___ | ___ | ___ |
| Cam UDP burst → h2 | ___ | ___ | ___ | ___ |
| sta2 web bursts (×50) | ___ | ___ | ___ | ___ |
| TempSensor telemetry | ___ | ___ | ___ | ___ |
| **Attacker only in blocked table?** | | ___ | | |
| Attacker ping loss / innocent ping loss | 100% / 0% | ___% / ___% | | |
| **Total false-positive blocks** | **0** | ___ | | |

## Phase 3 — Performance & scale (O4, O6, O7)
**3.1 Latency** (10 events, `grep Latency`): min ___ / mean ___ / max ___ ms
| Metric | Idle | Under flood | Limit | PASS? |
|---|---|---|---|---|
| Per-window compute (ms) | ___ | ___ | < 5000 | ___ |
| CPU (%) | ___ | ___ | — | ___ |
| RAM (%) | ___ | ___ | 8 GB | ___ |
| Disk (%) | ___ | ___ | — | ___ |
| Swap used? | ___ | ___ | none | ___ |

**3.3 Throughput ceiling:** saturates at ~___ pps (window compute reaches ___ ms).
**3.4 Resilience:** dashboard loaded during worst flood? ___ · `ipsctl` took effect? ___ · any hang/crash? ___

## Phase 4 — Adversarial / evasion, Kali (O8)
| Technique | Command | Evaded? | Caught by tier | Time to block | Notes |
|---|---|---|---|---|---|
| Insider via SDN (SYN @ `<vm-ip>:8080`) | `nping --tcp --flags syn …` | ___ | ___ | ___ | real ext IP? ___ |
| Outsider on controller NIC | `nmap -sS <t530-ip>` | ___ | `EXT-BLOCK` | ___ | iptables rule? ___ |
| Low-and-slow | `hping3 -S -p 80 -i u10000` | ___ | ___ | ___ | ___ |
| Randomized src ports | `hping3 --udp --flood --rand-source` | ___ | ___ | ___ | ___ |
| Slow HTTP | `slowhttptest -c 1000 …` | ___ | ___ | ___ | ___ |
| MAC/IP spoof | (attacker changes MAC) | ___ | ___ | ___ | re-block? ___ |
| **Caught / total** | | **___ / 6** | | | gaps: ___ |

## Phase 5 — Operational drill (O9)
| Step | Time | Done via | Notes |
|---|---|---|---|
| Noticed threat (dashboard) | ___ | dashboard | ___ |
| Identified attacker IP/MAC/tier | ___ | dashboard | ___ |
| Confirmed containment + continuity | ___ | ping/dashboard | ___ |
| FP-recovery: over-block → `UNBLOCK` → host returns | ___ | `ipsctl` | ___ |
| **Full loop total** | ___ s (target < 120) | | ___ |

---

## Findings & gaps (for Chapter 5 / the company report)
1. ___
2. ___
3. ___

## Evidence attached
☐ `redteam_run.log`  ☐ BLOCK-box screenshots  ☐ `/ips/blocked` JSON  ☐ `/ips/metrics` idle+flood
☐ `dump-flows` before/after  ☐ latency `grep` output  ☐ dashboard mid-attack  ☐ Phase-2 FP evidence
