# Mode B — t530 as the Wi-Fi AP + OVS (real-network deployment)

Turns the t530 into the Wi-Fi access point that phones / cameras / any-vendor IoT join, with all
their traffic crossing an **OVS bridge the IPS controller manages** — so every device is inspected
and blockable. Uses a **routed/NAT** design: clients sit on their own subnet behind the t530, NAT'd
out the wired NIC. This keeps `enp1s0` (and your SSH) untouched.

```
 phones / cameras / IoT / Kali  ──Wi-Fi──▶  wlan0 (hostapd AP)
                                              │  port of
                                          OVS  br-lan  ◀── managed by the Ryu IPS (OpenFlow :6633)
                                              │  NAT (MASQUERADE)
                                          enp1s0 ──▶ home router / internet
```

Your hardware: **Realtek GbE** = `enp1s0` (uplink); **Intel AC 3168 / AC 8265** = the Wi-Fi radio.

> ⚠ **Do this from the t530's own keyboard/console, not over SSH** — you'll be reconfiguring the
> network. If you must use SSH, connect over `enp1s0` (which this design does NOT touch).

---

## Step 0 — DECISIVE capability check (Intel AP mode)
Intel `iwlwifi` cards often **do not** support AP mode. Check before investing time:
```bash
iw dev                                   # note your Wi-Fi iface name (wlan0 / wlp2s0 / …). Use it below as <WIFI>.
iw list | sed -n '/Supported interface modes/,/interface combinations/p'
```
- If the list contains **`* AP`** → good, continue.
- If it does **NOT** list `AP` (common on AC 3168/8265) → the built-in card can't be an AP. **Get a
  USB Wi-Fi adapter with an AP-capable chipset** (Atheros AR9271, MediaTek MT7612U/MT7610U, Ralink
  RT5370 — all work out-of-the-box with hostapd), plug it in, and use *its* interface as `<WIFI>`.
  Everything below is identical. (This is the reliable path — don't fight Intel AP mode.)

Even when Intel lists `AP`, expect **2.4 GHz only, WPA2, limited clients**. If clients associate but
can't pass traffic through the bridge, that's the driver — switch to the USB adapter.

---

## Step 1 — packages
```bash
sudo apt update
sudo apt install -y hostapd dnsmasq openvswitch-switch iw rfkill iptables
sudo systemctl unmask hostapd            # Debian/Ubuntu ship it masked
sudo systemctl disable --now hostapd dnsmasq   # we start them by hand while testing
sudo rfkill unblock wlan
sudo iw reg set <CC>                      # your 2-letter country code (legal channels/power)
```

## Step 2 — the OVS bridge (managed by the IPS)
```bash
sudo ovs-vsctl add-br br-lan
sudo ovs-vsctl set bridge br-lan protocols=OpenFlow10       # controller is OpenFlow 1.0
sudo ovs-vsctl set-fail-mode br-lan standalone              # FAIL-OPEN: Wi-Fi keeps working if the
                                                            # controller stops. Use 'secure' to hard-
                                                            # enforce (no traffic without the IPS).
sudo ip addr add 192.168.50.1/24 dev br-lan                 # the t530 = gateway for AP clients
sudo ip link set br-lan up
```

## Step 3 — hostapd (bring `<WIFI>` up as the AP)
Create `/etc/hostapd/hostapd.conf` (edit `<WIFI>`, `<CC>`, SSID, passphrase; 2.4 GHz for Intel):
```ini
interface=<WIFI>
driver=nl80211
ssid=IPS-Lab
country_code=<CC>
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=ChangeMe-Strong-123
```
Start it and add the AP interface to the OVS bridge (order matters — AP up first):
```bash
sudo hostapd -B /etc/hostapd/hostapd.conf     # -B = background; drop -B once to watch for errors
sudo ovs-vsctl add-port br-lan <WIFI>
```
If hostapd errors with "could not configure driver mode" / "AP mode not supported" → Step 0 fallback.

## Step 4 — DHCP for clients (dnsmasq on br-lan)
Create `/etc/dnsmasq.d/ips-ap.conf`:
```ini
interface=br-lan
bind-interfaces
dhcp-range=192.168.50.50,192.168.50.200,12h
dhcp-option=3,192.168.50.1        # gateway = the t530
dhcp-option=6,1.1.1.1,8.8.8.8     # DNS
```
```bash
sudo systemctl restart dnsmasq
```

## Step 5 — NAT so clients reach the internet
```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o enp1s0 -j MASQUERADE
sudo iptables -A FORWARD -i br-lan -o enp1s0 -j ACCEPT
sudo iptables -A FORWARD -i enp1s0 -o br-lan -m state --state RELATED,ESTABLISHED -j ACCEPT
```
(These coexist with the IPS's own `IPS_EXTERNAL_BLOCK` iptables DROP rules — different chains/targets.)

## Step 6 — point the bridge at the IPS + set the config
```bash
sudo ovs-vsctl set-controller br-lan tcp:127.0.0.1:6633     # the controller's OpenFlow port (default 6633)
```
Edit `Controller/ips_config.json` for this network:
```json
{
  "lan_cidr": "192.168.50.0/24",
  "ext_whitelist": ["127.0.0.1", "192.168.50.1"],
  "protected_macs": []
}
```
`lan_cidr` = the AP subnet → AP clients are "internal" (blocked via OpenFlow DROP). A device on the
wired home side hitting the t530 is "external" (host iptables).

## Step 7 — launch the controller (monitor-only first)
```bash
cd ~/GP/Controller
sudo SNORT_PHYS_IFACE=enp1s0 SNORT_IFACES=snort_tap IPS_V2_FEATURES=1 \
  python3 -c "import collections,collections.abc; collections.MutableMapping=collections.abc.MutableMapping; from ryu.cmd.manager import main; main()" \
  Controller_main_Claude.py --wsapi-port 8081 2>&1 | tee controller_run.log
# in a 2nd terminal:
python3 ipsctl.py CONTROL:DETECT:ON
python3 ipsctl.py CONTROL:ML:OBSERVE       # LOG ONLY — no blocking until you've retrained (Phase 2)
```
Banner should load all tiers; `ips_config.json` load line should appear.

## Step 8 — verify + connect devices + Kali
```bash
curl -s http://127.0.0.1:8081/ips/switches            # -> {"count": 1}  (br-lan connected)
sudo ovs-ofctl dump-flows br-lan                       # rules appear as traffic flows
```
1. Join a **phone** to SSID `IPS-Lab` → it should get `192.168.50.x` and have internet.
2. Join your **cameras / IoT sensors** (any vendor) → confirm each MAC/IP shows up (dashboard /
   `/ips/blocked` should stay empty in monitor mode).
3. Join the **Kali** box to the same SSID → it's now an insider at `192.168.50.x`; its attacks cross
   `br-lan` → all 4 tiers see them.

Then follow `real_world_deployment_plan.md` Phase 1 → 2 (learn, then **retrain** on this network's
normal) before switching `CONTROL:ML:OBSERVE` → `AUTHORIZE`.

---

## Make it persistent (after it works manually)
Only once the manual bring-up is proven: put Steps 2–6 in a `systemd` oneshot unit (or
`/etc/rc.local`), enable `hostapd`/`dnsmasq` services, and persist iptables
(`netfilter-persistent save`). Keep the controller as its own `systemd` unit.

## Troubleshooting
| Symptom | Cause / fix |
|---|---|
| hostapd: "AP mode not supported" / "driver mode" | Intel card can't AP → USB AP-capable adapter (Step 0). |
| Clients associate but no internet | NAT/forwarding (Step 5) or DNS; check `sysctl net.ipv4.ip_forward`. |
| Clients associate but no traffic on `br-lan` | driver won't bridge the AP iface → USB adapter. |
| `/ips/switches` = 0 | `set-controller` port wrong, or controller's OpenFlow port ≠ 6633 (`ss -ltnp | grep 6633`). |
| A real device gets blocked at rest | you're past monitor mode without retraining — go back to OBSERVE + retrain; add its MAC to `protected_macs`. |
| Lost SSH | you touched `enp1s0` — this design shouldn't; recover at the console, keep `enp1s0` as plain DHCP. |
