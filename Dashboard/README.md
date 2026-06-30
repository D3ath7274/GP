# SDN-IPS Dashboard

A single-file, dependency-free web dashboard for the controller (`index.html`), built in the
**shadcn/ui** design language (the real zinc dark theme tokens, Card/Badge/Button/Progress/Table
components, lucide icons, Inter). It turns the flooded console into a glanceable view — see
`../dashboard_plan.md` for the design rationale.
**The backend is already wired into `Controller_main_Claude.py`** (read-only endpoints +
a serve route), so there is nothing to install or paste — just run the controller and open it.

> **One file, zero dependencies, served by the controller.** shadcn/ui is normally a Node/React
> build; here the same look is reproduced with hand-written CSS (the shadcn HSL tokens) + vanilla
> JS, so it needs **no CDN, no build, and works fully offline** on the t530. Deployment is
> unchanged: the controller serves this file at `GET /`.

## Use it (3 steps)
1. **Start the merged controller** (any wsapi-port; the t530 uses 8081 because nginx holds 8080):
   ```bash
   cd ~/GP/Controller
   sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=snort_tap IPS_V2_FEATURES=1 \
        ryu-manager Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
   ```
   (On Python 3.10 boxes where Ryu needs the shim, use the
   `python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()"` form instead of `ryu-manager`.)
2. **Open the dashboard in a browser:** `http://<controller-ip>:8081/`
   The controller serves `index.html` itself (route `GET /`), so it's **same-origin** — no CORS,
   no separate web server, no config.
3. That's it. It polls every 2 s and renders live state.

## What it shows
Status bar (DETECT/ML mode, switches), threat level, per-tier tiles, attack-type bar chart,
blocked-hosts table **with Unblock buttons**, deduped event timeline, and t530 health.

## Endpoints (all built into `Controller_main_Claude.py`, read-only)
| Endpoint | Returns |
|---|---|
| `GET /` | serves this `index.html` |
| `GET /ips/status` | mode, switches, blocked counts |
| `GET /ips/metrics` | alert totals, last-60s, per-attack counts, per-tier, confirmed attackers |
| `GET /ips/alerts` | last 50 Snort alerts (timeline) |
| `GET /ips/blocked` | blocked hosts (table) |
| `POST /ips/block` · `DELETE /ips/block/{ip}` | block / unblock (the Unblock button) |

## Notes
- **Port:** the dashboard auto-uses the same origin it's served from, so `--wsapi-port 8081`
  just works. If you instead open `index.html` as a local file, set `API_BASE` near the top of
  `index.html` to `http://<controller-ip>:8081` (and you'd then need a CORS header — simpler to
  use the served route in step 2).
- **No internet required:** the dashboard has no external scripts/fonts — the shadcn look is
  hand-written CSS + vanilla JS, so it renders identically online, air-gapped, or in a sandbox.
- `by_tier` currently reports **snort** (alert count) and **rate_dai** (confirmed attackers);
  RF/AE per-tier counters can be added later if you want those tiles populated.
- `PROJECT_DOCUMENTATION.md` (this folder) = what the whole system does + SOC deployment + comparison.
