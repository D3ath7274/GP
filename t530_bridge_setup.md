# HP t530 — Temporary Snort Bridge (just for the full system test)

*A throwaway VXLAN mirror so Snort on the t530 (controller) can see the Mininet VM's
data plane (`10.0.0.x`) during the full system check. **No systemd, no netplan, nothing
persistent** — it lives until you reboot or tear it down. Run the commands by hand in the
order below. (The permanent, reboot-surviving version is in
`SDN_IPS_Snort_Installation_Runbook.pdf` §7/§9 if you ever want it.)*

> Fill in the two **current** IPs (don't set static IPs for this — that's what locked you
> out. Use whatever the machines have now: `ip -br addr` on each; pin them later with a
> **router DHCP reservation** if you want them stable):
> - `T530_IP`    = the t530 controller's current IP (router showed e.g. `192.168.1.65`)
> - `MININET_IP` = the Mininet VM's current IP
>
> Fixed values (must match both sides): bridge `br-snort`, VXLAN keys `s1`=100, `ap1`=101.
> t530 NIC is **`enp1s0`** (not `ens33`).

**Prereqs:** Open vSwitch on both machines (`sudo systemctl status openvswitch-switch`),
Snort 3 built from source on the t530 (`/usr/local/bin/snort -V` → Snort++ 3.x), and the two
machines can **ping each other**. VXLAN uses UDP **4789** between them — fine on a flat LAN.

---

## Step 1 — t530: create the bridge (run once)
```bash
sudo ovs-vsctl --may-exist add-br br-snort
sudo ovs-vsctl --may-exist add-port br-snort vxlan-s1 \
  -- set interface vxlan-s1  type=vxlan options:remote_ip=<MININET_IP> options:key=100
sudo ovs-vsctl --may-exist add-port br-snort vxlan-ap1 \
  -- set interface vxlan-ap1 type=vxlan options:remote_ip=<MININET_IP> options:key=101
sudo ip link set br-snort up
sudo ovs-vsctl show          # GATE: br-snort with vxlan-s1 + vxlan-ap1
```
*(This is the whole t530 side. No `tc`/veth mirror — that only copies the t530's own NIC
traffic, which is just physical-LAN noise; the test only needs the Mininet plane.)*

## Step 2 — t530: start the controller against the bridge
```bash
cd ~/GP/Controller
sudo SNORT_IFACES=enp1s0,br-snort IPS_NO_TAP=1 IPS_V2_FEATURES=1 \
     ryu-manager Controller_main_Claude.py 2>&1 | tee controller_run.log
```
- `SNORT_IFACES=enp1s0,br-snort` + `IPS_NO_TAP=1` → Snort consumes the VXLAN bridge.
- If RF needs Python 3.9 on the t530 (sklearn 1.6.1), launch with
  `sudo … python3.9 -m ryu.cmd.manager Controller_main_Claude.py …` instead of `ryu-manager`.
- **GATE:** banner shows Snort started, `ML engine loaded`, `AE engine loaded`,
  `REST IPS API on :8080`, `UDP command listener … 9999`.

## Step 3 — Mininet VM: start the topology (points at the t530)
```bash
cd "~/GP/SDN Topology"
sudo mn -c && sudo CONTROLLER_IP=<T530_IP> python3 topology.py
```
This creates `s1` and `ap1` and connects them to the t530 over OpenFlow. **GATE:** `pingall`
= 0% loss; the t530 controller logs the switch connecting + REGISTER lines.

## Step 4 — Mininet VM: attach the mirrors (run once, AFTER Step 3)
`s1`/`ap1` only exist after the topology starts, so do this now (2nd terminal on the Mininet VM):
```bash
# s1  -> VXLAN key 100
sudo ovs-vsctl --if-exists clear bridge s1 mirrors
sudo ovs-vsctl --if-exists del-port s1 vxlan-snort-s1
sudo ovs-vsctl add-port s1 vxlan-snort-s1 \
  -- set interface vxlan-snort-s1 type=vxlan options:remote_ip=<T530_IP> options:key=100
sudo ovs-vsctl -- --id=@p get port vxlan-snort-s1 \
  -- --id=@m create mirror name=snort-mirror-s1 select-all=true output-port=@p \
  -- set bridge s1 mirrors=@m

# ap1 -> VXLAN key 101
sudo ovs-vsctl --if-exists clear bridge ap1 mirrors
sudo ovs-vsctl --if-exists del-port ap1 vxlan-snort-ap1
sudo ovs-vsctl add-port ap1 vxlan-snort-ap1 \
  -- set interface vxlan-snort-ap1 type=vxlan options:remote_ip=<T530_IP> options:key=101
sudo ovs-vsctl -- --id=@p get port vxlan-snort-ap1 \
  -- --id=@m create mirror name=snort-mirror-ap1 select-all=true output-port=@p \
  -- set bridge ap1 mirrors=@m

sudo ovs-vsctl list mirror   # GATE: snort-mirror-s1 / -ap1 present
```
*If you `mn -c` / restart the topology, `s1`/`ap1` are recreated — just re-run Step 4.*

## Step 5 — Verify the feed (t530)
```bash
sudo ovs-vsctl show                                            # br-snort + both vxlan ports
sudo tcpdump -i br-snort -nn -c 20                             # see 10.0.0.x once traffic flows
sudo /usr/local/bin/snort -T -c /etc/snort/sdn_ips.lua -i br-snort   # config self-test
curl -s http://127.0.0.1:8080/ips/status                       # REST API up
```
Then run an attack from the topology and confirm `🚨 IDS ALERT` + `[ML-OBSERVE]`/`[AE-OBSERVE]`
lines on the t530 (full procedure: `Controller_main_test_guide.md`).

## Teardown (after the test)
```bash
# t530
sudo ovs-vsctl --if-exists del-br br-snort
# Mininet VM (or just `sudo mn -c`, which drops s1/ap1 and their mirrors)
sudo ovs-vsctl --if-exists clear bridge s1  mirrors ; sudo ovs-vsctl --if-exists del-port s1  vxlan-snort-s1
sudo ovs-vsctl --if-exists clear bridge ap1 mirrors ; sudo ovs-vsctl --if-exists del-port ap1 vxlan-snort-ap1
```
Nothing survives a reboot, so a reboot also clears it.

---

## Even simpler — skip the bridge entirely (fallback)
If the VXLAN mirror gives you trouble, you don't strictly need a bridge: the controller's
**OpenFlow TAP** feeds Snort the data plane over the existing OpenFlow link. Just launch
**without** the bridge env vars:
```bash
cd ~/GP/Controller
sudo SNORT_PHYS_IFACE=enp1s0 IPS_V2_FEATURES=1 ryu-manager Controller_main_Claude.py 2>&1 | tee controller_run.log
```
(No Step 1, no Step 4.) This is how the controller VM worked before the bridge existed —
fine for a functional test; the VXLAN bridge is just more robust under heavy floods.

## Gotchas
- **t530 NIC is `enp1s0`** everywhere `ens33` used to appear.
- `br-snort: No such device` → re-run Step 1.
- `snort -V` says 2.x → wrong binary; use `/usr/local/bin/snort` (Snort 3 from source).
- VXLAN keys/bridge name must match exactly on both sides (`s1`=100, `ap1`=101, `br-snort`).
- Step 4 **must run after** the topology is up (s1/ap1 don't exist before that), and again after any `mn -c`.
- No traffic on `br-snort`? Confirm both machines ping each other and UDP 4789 isn't blocked.
