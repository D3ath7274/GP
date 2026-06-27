# IPS Dashboard — Plan (turn the flooded log into a glanceable view)

*A lightweight web dashboard for the SDN-IPS controller. The console today is a **firehose**
— `🚨 IDS ALERT` boxes, `[ML-OBSERVE]`/`[AE-OBSERVE]` lines, `port added/deleted`, per-window
`Traffic capture: N rows`. During a flood Snort alone fires thousands of lines/sec. The
dashboard's job is the opposite of the log: **aggregate, dedup, and show current state at a
glance**, with drill-down only when you ask for it.*

---

## 1. Design principle — why a dashboard beats the log
The log is **append-only and per-event**; a defender needs **current state and rates**. The
dashboard inverts four things:

| Flooded log | Dashboard |
|---|---|
| One line per packet/alert (150k/s under flood) | One row per **(attacker, attack-type)**, with a **count + last-seen** |
| Scrolls forever; the important line is gone in a second | **Latest state** stays on screen; history is a condensed timeline |
| All lines look equal | **Severity color** (green/amber/red) — eye goes to what matters |
| No totals | **Per-tier / per-class counts & rates** computed per window |
| Read-only | **Actionable** — unblock a host, flip DETECT/ML mode from the UI |

The rule throughout: **summarize by default, drill down on click.** Never stream raw per-packet
data to the browser.

---

## 2. Architecture — reuse what already exists
The merged controller (`Controller_main_Claude.py`) **already runs a WSGI REST API on :8080**
(`IPSRestController`, routes `/ips/status`, `/ips/blocked`, `/ips/switches`, `/ips/block`).
So the dashboard is **a few read-only JSON endpoints + one static HTML page** — no new server
process, no new dependency on the t530.

```
 browser (index.html, vanilla JS)  --poll every 1-2s-->  :8080 JSON endpoints
                                                          (same WSGI app, reads
                                                           in-memory controller state)
```

- **Backend:** extend the existing `IPSRestController` with read-only GETs that serialize state
  the controller already holds in memory (no new storage). Polling at 1–2 s is plenty — the
  capture window is 5 s.
- **Frontend:** one self-contained `dashboard/index.html` (vanilla JS `fetch` + hand-rolled
  **SVG** charts, *no CDN* so it works on an offline t530). Served by the controller via one
  extra route (`GET /` → the file) so it's same-origin (no CORS).
- **No framework, no build step** — keep it small for the 8 GB t530.

### Endpoints (exist vs add)
| Endpoint | Status | Feeds | Source in code |
|---|---|---|---|
| `GET /ips/status` | exists | status bar | controller flags |
| `GET /ips/blocked` | exists | blocked table | `_rest_blocked_ips` / `block_attacker` state |
| `GET /ips/switches` | exists | switch count | datapaths |
| `GET /ips/metrics` | **add** | counts/rates, per-tier, per-class, health | aggregate existing counters |
| `GET /ips/alerts?n=50` | **add** | event timeline (deduped) | `SnortManager._alerts` ring buffer |
| `GET /ips/devices` | **add** | device panel | `_discovered_names` + `traffic_capture` device profiles |
| `GET /` | **add** | serves `dashboard/index.html` | static file |

All "add" endpoints are **read-only and pull from in-memory state the controller already
maintains** (`snort_manager._alerts`, `traffic_capture._confirmed_attackers`,
`meta_controller_load`, per-class label counts) — so they're cheap and safe.

---

## 3. Panels (the actual screen)
Top-to-bottom, most-important-first:

1. **Status bar (always green/red):** controller up · Snort 3 running · RF loaded · AE loaded ·
   **DETECT** ON/OFF · **ML** OBSERVE/AUTHORIZE · switches connected · uptime.
   *One glance = "is the system healthy and in which mode."*

2. **Threat summary (the headline number):** active **confirmed attackers**, **blocked** hosts,
   **alerts in last 60 s**, and a single **threat level** chip (green/amber/red). Replaces
   "am I being attacked right now?" — which the log can't answer.

3. **Per-tier activity (4 tiles):** Snort (alerts/min + top SID), Rate+DAI (confirmations),
   RF (detections + avg confidence), AE (anomalies + avg confidence). Proves **each tier is
   alive and contributing** — the thing you currently grep the log for.

4. **Attack breakdown (bar chart):** live counts per type — ICMP / SYN / UDP / Port Scan /
   ARP / CPS. Replaces scrolling alert boxes with one chart.

5. **Blocked hosts (table, actionable):** IP · MAC · tier/reason · confidence · time ·
   **[Unblock]** button (calls `DELETE /ips/block/{ip}`). The one place you take action.

6. **Event timeline (condensed feed):** one line per *meaningful* event, deduped, e.g.
   `19:42:07  10.0.0.5 (TempSensor) → SYN Flood confirmed → BLOCKED  [Tier3 RF conf 0.87]`.
   This is the de-flooded replacement for the console — events, not packets.

7. **System health (t530-critical):** RAM (of 8 GB), CPU, **window compute time**
   (`meta_controller_load`, **must stay < 5000 ms**), backlog drops, throughput (pps/bps).
   This panel is also your **defense evidence** that the IPS runs within the thin client's budget.

8. **(Optional) Collection status:** during dataset capture — rows written, current label,
   per-class running counts. Useful while running `run_full_collection_hy`.

Color rule everywhere: green = normal, amber = flagged/observe-band, red = blocked/over-budget.

---

## 4. Build phases (incremental, each independently useful)
- **Phase 1 — MVP (~half a day):** add `GET /` (serve the page) + `GET /ips/metrics`; HTML with
  **status bar + threat summary + blocked table** polling the existing + new endpoints. Already
  more useful than the log.
- **Phase 2 — visibility:** add `GET /ips/alerts`; build **per-tier tiles + attack bar chart +
  event timeline** (dedup in the endpoint, keyed by `(src_ip, attack_type)` like the console's
  30 s dedup).
- **Phase 3 — health:** `GET /ips/metrics` gains RAM/CPU (`psutil`) + window compute + throughput;
  add **sparklines** (SVG) for alerts/min and compute-time over the last N windows.
- **Phase 4 — control & polish:** **[Unblock]** buttons, DETECT/ML-mode toggles (POST to a new
  `/ips/control` that maps to the existing UDP 9999 commands), collection panel, dark theme.

Phases 1–2 cover the demo; 3 gives you the thin-client resource story; 4 is gravy.

---

## 5. Tech notes / guardrails
- **No CDN, no framework, no DB.** Vanilla JS + SVG, state read live from controller memory.
  Survives an offline/airgapped t530.
- **Read-mostly.** Only `/ips/block` (delete) and the optional `/ips/control` mutate state — and
  both reuse paths that already exist (`block_attacker`, the UDP-9999 handlers).
- **Poll 1–2 s.** Don't push per-packet; the endpoints return *aggregates*, so payloads stay tiny
  even under a flood.
- **Cap list sizes** (`/ips/alerts?n=50`, blocked table) so the browser never has to render the
  firehose.
- **Same-origin** (served by the controller) → no CORS headaches; if you ever serve it elsewhere,
  add one `Access-Control-Allow-Origin` header in the WSGI response.

## 6. Definition of done
On the t530, during a live attack from the Mininet topology, the dashboard shows — **without
reading the console** — which host is attacking, which tier caught it, whether it's blocked, the
per-class counts, and that window compute stayed < 5 s. That's the whole point: **the operator
reads the dashboard, not the log.**
```
