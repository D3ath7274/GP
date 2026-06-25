# Snort 3 + Ryu IPS Integration

This repo now includes the standalone working Snort 3 + Ryu IPS flow from `~/Desktop/sdn-ips-project` without replacing the team's existing controller, ML model, datasets, topology, or verification files.

## Files

- `Controller/ryu_ips_app.py` - standalone OpenFlow 1.3 Ryu learning switch with REST block API.
- `Controller/snort_ryu_bridge.py` - local HTTP bridge from alert reader to Ryu REST API.
- `Controller/snort_alert_reader.py` - tails Snort 3 `alert_json.txt`, displays alerts, and blocks trusted SIDs.
- `Controller/snort3/sdn_ips.lua` - Snort 3 JSON alert config template.
- `Controller/snort3/sdn_ips_local.rules` - local rules with SIDs consumed by the alert reader.
- `Controller/scripts/*.sh` - install, startup, bridge/VXLAN, firewall, and verification helpers.

The existing `Controller/Controller.py` path remains the team integrated mode with ML, traffic capture, `snort_monitor.py`, `traffic_mirror.py`, and dataset generation.

The standalone Snort config intentionally loads `/etc/snort/rules/sdn_ips_local.rules`.
Do not put standalone IPS rule updates only in `/etc/snort/rules/local.rules`; that
file is not used unless `sdn_ips.lua` is edited to include it.

For the exact standalone file list, see `Controller/STANDALONE_SNORT_RYU_FILES.md`.
When testing this standalone flow, do not run `Controller.py`, `snort_monitor.py`,
or `snort_setup.sh`; those belong to the team integrated ML/dataset controller
path and use different Snort config/output files.

## Startup Order

Use separate terminals on the Controller VM unless noted.

1. Topology

   On the Topology VM, confirm `SDN Topology/topology.py` points at the Controller VM IP:

   ```bash
   cd /path/to/GP/SDN\ Topology
   sudo python3 topology.py
   ```

2. Ryu controller

   On the Controller VM:

   ```bash
   cd /path/to/GP/Controller
   ./scripts/start_snort_ryu_ips.sh
   ```

3. Snort-to-Ryu bridge

   ```bash
   cd /path/to/GP/Controller
   python3 snort_ryu_bridge.py
   ```

4. Snort alert reader

   ```bash
   cd /path/to/GP/Controller
   sudo python3 snort_alert_reader.py
   ```

5. Snort

   Install the project config once:

   ```bash
   cd /path/to/GP/Controller
   sudo ./scripts/install_snort3_ips_config.sh
   sudo snort -c /etc/snort/sdn_ips.lua -T
   ```

   Start Snort on the mirrored interface:

   ```bash
   cd /path/to/GP/Controller
   sudo SNORT_IFACE=br-snort ./scripts/start_snort3_json.sh
   ```

   If you are using the existing team controller TAP mirror instead of VXLAN, use `SNORT_IFACE=snort_tap`. For direct physical capture, use the Controller VM NIC, for example `SNORT_IFACE=ens33`.

6. Verification commands

   ```bash
   cd /path/to/GP/Controller
   ./scripts/verify_snort_ryu_ips.sh
   curl -s http://127.0.0.1:8080/ips/blocked
   tail -f /var/log/snort/alert_json.txt
   ```

## Optional VXLAN/br-snort Mirror

If traffic is mirrored between VMs using VXLAN:

```bash
cd /path/to/GP/Controller
sudo LOCAL_IP=<controller-vm-ip> REMOTE_IP=<topology-vm-ip> ./scripts/setup_vxlan_br_snort.sh
sudo SNORT_IFACE=br-snort ./scripts/start_snort3_json.sh
```

## Team Integrated Mode

For the existing team controller with ML/dataset capture:

```bash
cd /path/to/GP/Controller
# one-time: install the curated Snort 3 config + rules (requires Snort 3)
sudo ./scripts/install_snort3_ips_config.sh
sudo IPS_V2_FEATURES=1 ryu-manager Controller.py
```

Then start the topology:

```bash
cd /path/to/GP/SDN\ Topology
sudo python3 topology.py
```

This mode now launches Snort 3 itself (per monitored interface) using the **same**
curated `/etc/snort/sdn_ips.lua` + `sdn_ips_local.rules` as the standalone flow, and
`snort_monitor.py` tails the structured **`alert_json`** output (replacing the old
Snort 2.x `snort.conf` + `alert_fast` path). Blocking is done in-process by
`Controller.py` (OpenFlow DROP via `block_attacker`), so do **not** also run the
standalone `snort_ryu_bridge.py` / `snort_alert_reader.py` against the same alerts
unless you intentionally want both blocking paths active.

## Troubleshooting

If `br-snort` sees external ICMP traffic but Snort does not produce SID `1000001`,
verify the active files on the Controller VM:

```bash
grep -n "sdn_ips_local.rules" /etc/snort/sdn_ips.lua
grep -n "sid:1000001" /etc/snort/rules/sdn_ips_local.rules
```

The active SID `1000001` rule should use:

```text
alert icmp any any -> any any (msg:"ICMP Flood"; itype:8; detection_filter:track by_src, count 10, seconds 5; sid:1000001; rev:2;)
```

If `/etc/snort/rules/local.rules` has a newer rule but `sdn_ips_local.rules` does
not, rerun `sudo ./scripts/install_snort3_ips_config.sh` from `Controller/`.

If Snort alerts but the target still receives external packets, verify
`snort_alert_reader.py` is running with sudo and check the chain used by the
working reader:

```bash
sudo iptables -S INPUT | grep <attacker-ip>
```

If Snort prints decoder SID `6` with `(ipv4) IPv4 datagram length > captured
length`, Snort is seeing truncated/offloaded frames before ICMP rule matching.
Disable capture offloads on the mirror path and run Snort with a full snaplen:

```bash
cd /path/to/GP/Controller
sudo ./scripts/disable_capture_offloads.sh br-snort vxlan-snort <physical-nic>
sudo SNORT_IFACE=br-snort SNORT_SNAPLEN=65535 ./scripts/start_snort3_json.sh
```

After this, external ICMP floods should emit SID `1000001`, not only decoder SID
`6`.
