# Firewall & WAF Integration Plan

Extend the SDN IPS from a two-backend L2–L4 blocker into a **layered defense with one brain and
three enforcement planes**: the SDN data plane (OpenFlow), a real **network firewall** (L3/L4), and a
**Web Application Firewall** (L7). The IPS stays the *decision* engine; the firewall and WAF become
*enforcement* muscle that share the IPS's block intelligence.

---

## 0. The idea in one line
Keep the 4-tier detection brain, but stop treating "block" as "shell out to `iptables -I`." Turn block
into a decision that fans out to **pluggable enforcement backends** (SDN, firewall, WAF) over a
**shared blocklist**, and add a **5th detection tier (the WAF)** that feeds L7 attacks back into that
same brain.

---

## 1. Where you are now (gap analysis)

| Layer | What exists today | Gap |
|---|---|---|
| **SDN data plane (L2–L4)** | `_do_block_attacker` installs OpenFlow `dl_src`/`nw_src` DROP flows | Works, but only inside the OVS bridge |
| **Host firewall (L3/L4)** | `_block_external_ip` does `iptables -I INPUT/FORWARD -s <ip> -j DROP`, one rule per attacker | **Not a firewall** — no base policy, no default-deny, no zones, O(n) rule scan, `-C` shell-out per block, no stateful ruleset management |
| **Application layer (L7)** | *nothing* — the pipeline is flow-features + signatures; no HTTP parsing | **Blind to SQLi / XSS / LFI / RCE / path traversal / credential stuffing** — the entire OWASP Top 10 |
| **Correlation / sharing** | Each backend is hardcoded in `_block_worker` | No shared blocklist; L7 and L3 can't inform each other |

**Two concrete deficiencies to fix:**
1. The "firewall" is a reactive blocklist bolted onto the host, not a managed stateful firewall.
2. There is no application-layer inspection at all, so a web attack that rides valid TCP:443 flows
   sails straight through every current tier.

---

## 2. Target architecture — one brain, three enforcement planes

```
            DETECTION BRAIN  (your IPS = Policy Decision Point)
  Tier1 Snort   Tier2 rate/DAI   Tier3 RF   Tier4 AE   [NEW] Tier5 WAF/ModSec (L7)
                                   │
                                   ▼
                    block decision → _block_q → _block_worker
                                   │   (pluggable enforcement adapters, config-selected)
        ┌──────────────────────────┼───────────────────────────────┐
        ▼                          ▼                                ▼
  OpenFlow DROP            Network Firewall                    WAF deny
  (SDN dataplane,          (nftables set  OR                   (ModSecurity blocklist
   _do_block_attacker)      pfSense/OPNsense API)               rule)
        └────────────────── SHARED BLOCKLIST (the common currency) ──────────────┘
```

- **Brain (PDP):** unchanged 4 tiers + a new L7 tier. It only *decides*.
- **Three enforcement planes (PEP):** SDN, firewall, WAF. Each is a plug-in reading the shared
  blocklist / receiving block ops.
- **Shared blocklist:** the single source of truth every plane consumes. The IPS writes; SDN,
  firewall, and WAF read. This is what makes it *one system* instead of three tools.

---

## 3. Part A — Network Firewall integration

Goal: replace the ad-hoc `iptables -I` blocklist with a **managed stateful firewall** the IPS drives.
Two deployment shapes; ship A1 as the default, offer A2 for sites that already own a firewall.

### A1 — Embedded managed firewall via **nftables** (recommended default; self-contained appliance)
The IPS owns a dedicated nftables table and drives it as a real firewall:

- **Base policy (static, shipped once):** default-deny inbound on the untrusted side, stateful
  `ct state established,related accept`, an allow-list for management (SSH from the admin subnet),
  and one rule that drops anything in the IPS block set.
- **Dynamic blocks (what the IPS writes):** a named set `ips_blocklist_v4 { type ipv4_addr; flags
  timeout; }`. A block = *add one element to the set*; an unblock = *delete the element*. One rule
  matches the whole set.
- **Timed blocks for free:** nftables set `timeout` replaces your Python `_block_duration`
  bookkeeping — the kernel expires the element itself.

**Why nftables sets instead of `iptables -I` (the rationale):** `iptables -I -s <ip>` inserts a
*separate rule per attacker*. Under a scan with hundreds of source IPs you get hundreds of linear-scanned
rules, and your current code shells out `iptables -C` to check each one — O(n) memory *and* O(n) per
packet. An nftables named set is a **hash set**: membership is O(1), add/remove is **atomic** without
rebuilding the ruleset, and it's exactly how CrowdSec / fail2ban / modern firewalls do dynamic
blocking. This single change is the biggest correctness + performance win in Part A, and it's why real
firewalls are set-based.

Maps onto code: `_block_external_ip` / `_unblock_external_ip` become a **`NftablesBackend`** (add/del a
set element) instead of insert/delete a rule.

### A2 — External firewall as the enforcer (IPS drives it by API)
For a site with an existing perimeter firewall (pfSense / OPNsense / a Linux router), the IPS should
**drive** it, not fight it:

- **pfSense / OPNsense:** maintain a blocklist *alias* (pfBlockerNG URL table or the OPNsense REST
  API); a single firewall rule drops that alias. The IPS adds/removes the attacker via the API.
- **Generic Linux router:** push to the router's own nftables set over SSH / a small agent.

This is the **PDP/PEP split** again: IPS decides, the firewall enforces at the perimeter. Same
`block(target)` interface, different backend.

### A3 — Feedback loop (firewall → IPS, optional, phase 3)
Tail the firewall's drop log (nftables `log prefix "ips-drop"` or the pfSense filter log) and feed
perimeter hits back into the controller as another signal — the same pattern your Snort reader already
uses. Turns the firewall from a dumb actuator into a sensor too.

---

## 4. Part B — WAF integration (the bigger, higher-value piece)

Goal: add L7/HTTP inspection and wire it into the brain so an application-layer attacker is **blocked
at the network layer**, not just for one request.

### B1 — Deploy ModSecurity v3 + OWASP Core Rule Set as a reverse proxy (the new Tier 5)
- **Stack:** nginx (or Apache) + `libmodsecurity3` + the OWASP **Core Rule Set (CRS)**, deployed as a
  reverse proxy in front of each protected web app: `client → WAF(nginx+ModSec+CRS) → web app`.
  Blocks SQLi / XSS / LFI / RCE / path traversal / protocol anomalies at L7.
- **Modern alternative:** **Coraza** (Go, ModSecurity-rule-compatible, easy to embed / lower
  footprint) — worth it on the t530's modest CPU. Same rule language, same audit-log integration.
- Conceptually the WAF is **Tier 5** of your detection stack: signature/anomaly detection, but at the
  application layer.

### B2 — WAF → IPS escalation (the integration that matters)
ModSecurity writes a structured JSON audit log per event (rule id, anomaly score, client IP, URI).
Add **`Controller/waf_alert_reader.py`** — a near-clone of your existing `snort_alert_reader.py` /
`snort_monitor.py` — that tails that log and, when a client crosses an anomaly-score / repeat
threshold, calls the controller (POST `/ips/block` or the UDP control channel).

**Effect:** an attacker running `sqlmap` against the web app gets **kicked off the network entirely**
(OpenFlow + firewall DROP), not merely served a 403 for that one request. L7 *detection* drives
L3/L4 *enforcement*. This is the cross-layer correlation that makes the three planes one system.

Maps onto code: add **`_handle_waf_alert`** modeled on `_handle_snort_alert` (line ~419), gated by the
same `_detection_enabled` flag, resolving the client IP to a block op on `_block_q`.

### B3 — IPS → WAF (shared blocklist deny)
Push the IPS blocklist *to* the WAF as well: a ModSecurity rule that denies any request whose client IP
is in the shared blocklist. So a host flagged by **RF/AE at the network layer** is also denied at L7 —
symmetry in both directions. The **shared blocklist is the common currency** between all three planes.

### B4 — Tuning discipline (mirror your OBSERVE→AUTHORIZE flow)
CRS in blocking mode is famously noisy. Run ModSecurity in **DetectionOnly** first (log, don't block),
tune out false positives, then flip to blocking — the exact parallel of your `ML:OBSERVE →
ML:AUTHORIZE` graduation. Reuse that mental model and, ideally, the same dashboard gate ("0 L7 blocks
at rest on real traffic").

---

## 5. The refactor that makes both clean — enforcement adapters (Phase 0)

Today `_block_worker` hardcodes "OpenFlow + iptables." Before adding firewall and WAF, extract a tiny
interface so each plane is a **plug-in**, not another `if` branch:

```python
class EnforcementBackend:            # in Controller/enforcement.py
    def block(self, target): ...     # target = {ip, mac, reason, ttl}
    def unblock(self, target): ...

# concrete: OpenFlowBackend (wraps _do_block_attacker), NftablesBackend,
#           PfSenseBackend, WafBlocklistBackend
```

`_block_worker` then loops over the **configured** backends and calls `block()/unblock()` on each.
`ips_config.json` selects which planes are active per deployment.

**Rationale:** without this, firewall + WAF integration means scattering conditionals through the
hot block path (which runs on the hub greenlet — the concurrency-sensitive spot). With it, each plane
is isolated, independently testable, and enable/disable is config, not code. It also keeps the
eventlet-hub safety intact: adapters that shell out (nftables, WAF API) are safe from the worker
greenlet exactly like `_block_external_ip` is today; only OpenFlow `send_msg` must stay on the hub.

---

## 6. Phased roadmap

| Phase | Deliverable | Files touched |
|---|---|---|
| **0 — Adapter refactor** | Extract `EnforcementBackend`; port existing OpenFlow + iptables into it; config-select | `Controller_main_Claude.py` (`_block_worker`), new `Controller/enforcement.py`, `ips_config.json` |
| **1 — Network firewall** | `NftablesBackend` (base policy + `ips_blocklist` timeout set); shared blocklist store | `Controller/enforcement.py`, new `Controller/firewall/nft_base.nft`, `Controller/shared_blocklist.py` |
| **2 — WAF core** | ModSecurity+CRS reverse proxy (DetectionOnly); `waf_alert_reader.py` → `/ips/block`; `_handle_waf_alert` (Tier 5) | new `Controller/waf/` (nginx+modsec+CRS conf), `Controller/waf_alert_reader.py`, `Controller_main_Claude.py` |
| **3 — Bidirectional + external FW + UI** | `WafBlocklistBackend` (IPS→WAF deny); `PfSenseBackend`; firewall/WAF logs as signals; dashboard L7 + firewall panels | `Controller/enforcement.py`, `Dashboard/index.html`, `/ips/status` + `/ips/metrics` |
| **4 — Harden + test** | Red-team both planes; flip WAF to blocking after tuning; (optional) L7 features + retrain | `red_team_test_runbook.md`, tests |

---

## 7. Config changes (`ips_config.json`)

```json
{
  "lan_cidr": "10.0.0.0/8",
  "ext_whitelist": ["127.0.0.1", "::1"],
  "protected_macs": [],
  "enforcement": {
    "backends": ["openflow", "nftables"],
    "nftables": { "table": "ips", "set_v4": "ips_blocklist_v4", "default_ttl": 0 }
  },
  "waf": {
    "enabled": true,
    "mode": "DetectionOnly",
    "audit_log": "/var/log/modsec/audit.json",
    "block_score": 15,
    "push_blocklist": true
  }
}
```

`enforcement.backends` = which planes fire on a block. `waf.mode` = the OBSERVE→AUTHORIZE knob for L7.

---

## 8. Testing / red-team

- **Firewall:** `nmap -sS` / `hping3` from Kali → confirm the attacker lands in the `ips_blocklist`
  set (`nft list set ips ips_blocklist_v4`) and traffic stops; confirm timed entries expire.
- **WAF:** `sqlmap`, `nikto`, a manual `?id=1' OR '1'='1` → confirm ModSec logs the hit, then confirm
  `waf_alert_reader` escalated it into a **network** block (the same IP now dropped by OpenFlow/nft),
  not just a 403.
- **Cross-layer proof:** show one Kali IP doing an L7 attack getting dropped at L3 — the money demo.
- **No-false-positive gate at rest:** real browsing / normal API calls → 0 WAF blocks in blocking mode
  after tuning (mirrors the ML at-rest gate).

---

## 9. Risks & tradeoffs (the rationale)

- **TLS visibility:** a WAF must terminate TLS to read HTTP, so it holds the web app's cert and becomes
  a reverse proxy. That's a real trust/deployment decision — the WAF sees plaintext requests. Fine for
  apps you own; document it.
- **Don't run two firewall managers on one policy:** if you adopt nftables, stop using `iptables -I`
  for blocks (they can shadow each other). Migrating mid-deployment can **drop your SSH** — same
  lockout risk as `IPS_EXTERNAL_BLOCK`; put the management allow-rule in the base policy **first**.
- **WAF false positives:** CRS blocking mode is noisy → DetectionOnly-first is mandatory, not optional.
- **Ordering:** the WAF only sees requests that *reach* the web app. If the firewall already dropped
  the host, the WAF never sees it — good for defense-in-depth, but for *detection* the WAF must sit
  inline before enforcement so it can be the one to spot the L7 attack in the first place.
- **Performance on the t530:** ModSec+full CRS adds latency and CPU; prefer Coraza or a trimmed rule
  set on modest hardware.
- **Concurrency:** new backends shell out (nft, WAF API) → safe off the worker greenlet like the
  existing iptables backend; never call OpenFlow `send_msg` from anywhere but the hub. The adapter
  refactor preserves this boundary.

---

## 10. What this gives you
A single console (your existing dashboard + `/ips/*` API) that correlates **network-layer** and
**application-layer** attacks and enforces across **SDN + firewall + WAF** from one brain — i.e. a
small **Unified Threat Management** system built on the detection engine you already have. For the
thesis it's a clean "defense in depth across OSI layers" story; as a product it's the difference
between "an SDN flow blocker" and "a security appliance."
