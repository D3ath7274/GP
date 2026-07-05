# QoS — Adaptive Traffic Steering (SD-WAN path priority)

A standalone SD-WAN **traffic-steering** component: it chooses, per flow, whether to send
traffic down a **fast path** or a **backup path** based on the application class and a
customer policy — the "predictive traffic steering" that the main thesis scoped as future
work. It runs as its own **OpenFlow 1.3** Ryu app on a 4-switch topology, separate from the
OF 1.0 IPS controller, and mirrors all edge traffic to the IPS for inspection.

## Files
| File | Role |
|---|---|
| `smart_controller.py` | OF 1.3 Ryu app: classify → apply policy → steer fast/backup + mirror to IPS |
| `smart_topology.py` | Mininet-WiFi 4-switch dual-path SD-WAN testbed |
| `config.json` | Customer policy (priority app class + rate threshold) |

## Topology (`smart_topology.py`)
```
                 ┌── s2 ──┐   FAST  : 100 Mbit, 2 ms   (s1 port 4)
  stations/hosts │        │
      ──── s1 ───┤        ├─── s4 ──── h2 (10.0.0.4)
       (edge)    │        │
                 └── s3 ──┘   BACKUP : 50 Mbit, 15 ms  (s1 port 5)
```
- Edge switch **s1** (dpid `0x11`): `ap1`→p1, `h1`→p2, `h3`→p3, **fast uplink**→p4,
  **backup uplink**→p5, **IPS server (10.0.0.99)**→p6.
- IoT / "fast" stations: `sta1` (10.0.0.1), `sta2` (10.0.0.2). Normal: `sta3` (10.0.0.5),
  `h3` (10.0.0.6). Servers: `h1` (10.0.0.3), `h2` (10.0.0.4).
- Fast leg `s1→s2→s4` (100 Mbit/2 ms); backup leg `s1→s3→s4` (50 Mbit/15 ms).

## Steering logic (`smart_controller.py`)
1. **Classify** each flow by L4 destination port:
   - IoT → `1883` (MQTT), `5683` (CoAP), `9000`; Web → `80`/`443`.
   - Fallback: traffic to/from `10.0.0.1/2/3` is treated as IoT (keeps older tests working).
2. **Policy** (`config.json`): `priority_traffic` = which class is VIP; a rate threshold.
3. **Decision:** if `traffic_type == priority_traffic` **and** the traffic is "high" →
   **fast path** (s1 out-port 4, s4 out-port 2); otherwise **backup path** (s1 p5, s4 p3).
   Logged as `[FAST PATH - VIP]` / `[BACKUP PATH]`.
4. **IPS mirror:** every flow through `s1` is also copied to port 6 (the IPS server); packets
   arriving *from* the IPS port are dropped to avoid loops. Per-flow rules use `idle_timeout=3`
   so a policy change in `config.json` is re-applied within a few seconds (auto-reload).

## Run
```bash
# 1) controller (OpenFlow 1.3, port 6653)
cd QoS
ryu-manager smart_controller.py            # reads ./config.json

# 2) topology (Mininet-WiFi) — set CONTROLLER_IP first
sudo python3 smart_topology.py
```
Demonstrate steering by sending to a priority port and watching the log flip paths:
```bash
mininet-wifi> h1 iperf -s -p 1883 &                 # IoT service on h2/h1
mininet-wifi> sta1 iperf -c 10.0.0.3 -p 1883        # → [FAST PATH - VIP]
mininet-wifi> sta1 iperf -c 10.0.0.3 -p 8080        # → [BACKUP PATH]
```

## Integration notes & known gaps
- **Separate controller, by design.** This is OF 1.3 on a 4-switch SD-WAN; the IPS
  (`Controller/Controller_main_Claude.py`) is OF 1.0 on a single switch. They are complementary
  — the steering app **mirrors to the IPS** (s1 port 6 → 10.0.0.99). Running both as *one*
  controller process is a larger future task (OF-version + topology unification).
- **Rate threshold not yet wired.** `config.json` carries `threshold_mbps`, but the controller
  currently reads a boolean `traffic_is_high` (defaulting to `True`) — so a priority-class flow
  is steered to the fast path *regardless of its measured rate*. To honour "path priority by
  needed data rate," add per-flow byte-count sampling (e.g. `OFPFlowStats` polling or an
  `OFPMeterMod`) and set `traffic_is_high` from `rate ≥ threshold_mbps`.
- **Set `CONTROLLER_IP`** in `smart_topology.py` (currently `192.168.1.7`) and keep the
  controller on port **6653**.
- The vendored `mininet-wifi` / `ryu` / `hostapd` build trees from the original
  "Quality Of Service part" folder are **not** committed — only these three source files are.
