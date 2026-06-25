# HP t530 — Permanent Snort Bridge Replication

*Replicates the permanent VXLAN `br-snort` mirror from
`SDN_IPS_Snort_Installation_Runbook.pdf` (lab default controller=192.168.1.200,
mininet=192.168.1.201) onto the **t530 deployment**. The t530 is the **controller**;
the Mininet machine mirrors its OVS (`s1` key 100, `ap1` key 101) to the t530's
`br-snort` over VXLAN, and the t530 `tc`-mirrors its NIC ingress into `br-snort`.
Both systemd units make it survive reboots and topology restarts.*

> Fill these in first (then the blocks below are copy-paste):
> - `T530_IP`   = the t530 controller's static IP (lab default would be 192.168.1.200)
> - `MININET_IP`= the Mininet machine's static IP (lab default 192.168.1.201)
> - `EXT_IF`    = the t530's bridged interface (check `ip -br addr`; lab default `ens33`)
> VXLAN keys **must match** both sides: `s1`=100, `ap1`=101. Bridge name stays `br-snort`.

Prereqs on both machines (from the PDF §4/§8): Open vSwitch installed + enabled
(`sudo apt install -y openvswitch-switch && sudo systemctl enable --now openvswitch-switch`),
plus Snort 3 from source on the t530 (PDF §5 — **do not** `apt install snort`, that's v2).

---

## A. Static IPs (both machines, netplan)
**t530 (controller):**
```bash
IFACE=ens33; CONTROLLER_IP=<T530_IP>; GATEWAY=192.168.1.1
sudo tee /etc/netplan/01-sdn-controller-static.yaml >/dev/null <<EOF
network:
  version: 2
  renderer: NetworkManager
  ethernets:
    $IFACE: {dhcp4: false, addresses: [$CONTROLLER_IP/24],
      routes: [{to: default, via: $GATEWAY}], nameservers: {addresses: [8.8.8.8,1.1.1.1]}}
EOF
sudo netplan apply && ip -br addr
```
**Mininet machine:** same, file `01-sdn-mininet-static.yaml`, `addresses: [<MININET_IP>/24]`.

## B. t530 controller bridge — `br-snort.service` (PDF §7)
```bash
sudo tee /usr/local/sbin/setup-br-snort.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
set -e
MININET_IP="<MININET_IP>"      # <-- fill in
EXT_IF="ens33"                 # <-- t530 interface if different
ovs-vsctl --may-exist add-br br-snort
ovs-vsctl --may-exist add-port br-snort vxlan-s1 \
  -- set interface vxlan-s1 type=vxlan options:remote_ip=$MININET_IP options:key=100
ovs-vsctl --may-exist add-port br-snort vxlan-ap1 \
  -- set interface vxlan-ap1 type=vxlan options:remote_ip=$MININET_IP options:key=101
ip link set br-snort up
ip link show veth-mirror0 >/dev/null 2>&1 || ip link add veth-mirror0 type veth peer name veth-mirror1
ip link set veth-mirror0 up; ip link set veth-mirror1 up
ovs-vsctl --may-exist add-port br-snort veth-mirror1
tc qdisc del dev $EXT_IF ingress 2>/dev/null || true
tc qdisc add dev $EXT_IF ingress
tc filter add dev $EXT_IF parent ffff: protocol ip u32 match u32 0 0 \
  action mirred egress mirror dev veth-mirror0
ovs-vsctl show
EOF
sudo chmod +x /usr/local/sbin/setup-br-snort.sh
sudo tee /etc/systemd/system/br-snort.service >/dev/null <<'EOF'
[Unit]
Description=Create br-snort monitoring bridge for SDN IPS
After=network-online.target openvswitch-switch.service
Wants=network-online.target
Requires=openvswitch-switch.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/setup-br-snort.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now br-snort.service
sudo systemctl status br-snort.service --no-pager
ip -br link | grep -E "br-snort|vxlan|veth-mirror"
```

## C. Mininet machine mirror — `mininet-snort-mirror.service` (PDF §9)
```bash
sudo tee /usr/local/sbin/mininet-snort-mirror-watch.sh >/dev/null <<'EOF'
#!/usr/bin/env bash
CONTROLLER_IP="<T530_IP>"       # <-- fill in (the t530)
configure() {  # $1=bridge $2=key
  ovs-vsctl --if-exists clear bridge $1 mirrors
  ovs-vsctl --if-exists del-port $1 vxlan-snort-$1
  ip link delete vxlan-snort-$1 2>/dev/null || true
  ovs-vsctl add-port $1 vxlan-snort-$1 \
    -- set interface vxlan-snort-$1 type=vxlan options:remote_ip=$CONTROLLER_IP options:key=$2
  ovs-vsctl -- --id=@p get port vxlan-snort-$1 \
    -- --id=@m create mirror name=snort-mirror-$1 select-all=true output-port=@p \
    -- set bridge $1 mirrors=@m
}
while true; do
  ovs-vsctl br-exists s1  && configure s1  100
  ovs-vsctl br-exists ap1 && configure ap1 101
  sleep 10
done
EOF
sudo chmod +x /usr/local/sbin/mininet-snort-mirror-watch.sh
sudo tee /etc/systemd/system/mininet-snort-mirror.service >/dev/null <<'EOF'
[Unit]
Description=Auto configure Mininet OVS mirrors to Snort controller
After=network-online.target openvswitch-switch.service
Wants=network-online.target
Requires=openvswitch-switch.service
[Service]
Type=simple
ExecStart=/usr/local/sbin/mininet-snort-mirror-watch.sh
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now mininet-snort-mirror.service
sudo systemctl status mininet-snort-mirror.service --no-pager
```

## D. Run the merged controller against `br-snort`
On the t530, point Snort at the bridge (not the OpenFlow TAP) so it consumes the
VXLAN-mirrored data plane — and set the topology to reach the t530:
```bash
# t530 (controller):
cd ~/.../GP/Controller
sudo SNORT_IFACES=ens33,br-snort IPS_NO_TAP=1 IPS_V2_FEATURES=1 \
     ryu-manager Controller_main_Claude.py 2>&1 | tee controller_run.log

# Mininet machine:
cd "~/.../GP/SDN Topology"
sudo CONTROLLER_IP=<T530_IP> python3 topology.py   # or edit CONTROLLER_IP in topology.py
```
- `SNORT_IFACES=ens33,br-snort` → Snort watches the physical NIC + the VXLAN bridge.
- `IPS_NO_TAP=1` → disables the in-process `snort_tap` mirror (avoids double-feeding Snort).
- `CONTROLLER_IP=<T530_IP>` → topology's OpenFlow + UDP 9999 go to the t530.

## E. Verify (PDF §10–§11)
```bash
# t530 (controller)
sudo ovs-vsctl show                         # br-snort with vxlan-s1/ap1 + veth-mirror1
sudo tcpdump -i br-snort -nn -c 20          # see mirrored 10.0.0.x + external traffic
sudo /usr/local/bin/snort -T -c /etc/snort/sdn_ips.lua -i br-snort   # config self-test
curl -s http://127.0.0.1:8080/ips/status    # REST API up (merged controller)
# Mininet machine (after topology starts)
sudo ovs-vsctl list mirror                  # snort-mirror-s1 / -ap1 present
```
Then run an attack from the topology and confirm Snort alerts + `[ML-OBSERVE]`/
`[AE-OBSERVE]` lines on the t530 (see `Controller_main_test_guide.md`).

## Gotchas (PDF §12)
- `br-snort: No such device` → `sudo systemctl start br-snort.service` (or run the script).
- `VXLAN File exists` → stale interface; the watcher deletes `vxlan-snort-*` before re-adding.
- Snort prints `Snort 2.x` → wrong binary; use `/usr/local/bin/snort` (Snort 3 from source).
- Keys/bridge names must match exactly on both machines (`s1`=100, `ap1`=101, `br-snort`).
- If the t530's interface isn't `ens33`, set `EXT_IF` (script B) and `SNORT_PHYS_IFACE` /
  `SNORT_IFACES` accordingly.
