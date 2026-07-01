from mininet.node import RemoteController
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
import time
import threading
import socket as _socket

# Controller physical IP (used for direct UDP commands).
# Static lab default per the install runbook: controller VM = .200, mininet VM = .201.
# Override with the env var CONTROLLER_IP when deploying on the t530 / a different LAN.
import os as _os
CONTROLLER_IP = _os.environ.get('CONTROLLER_IP', '192.168.1.200')
CONTROLLER_CMD_PORT = 9999

def _send_to_controller(msg):
    """Send a UDP command directly to the controller over the physical network."""
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.sendto(msg.encode(), (CONTROLLER_IP, CONTROLLER_CMD_PORT))
        s.close()
    except Exception as e:
        print(f"*** Error sending to controller: {e}")

def register_iot_device(net, name, ip, mac, switch_name, device_type):
    """
    Dynamically adds an IoT device and registers it with the controller.
    Usage in CLI: py net.register_iot_device(net, 'iot1', '10.0.0.5/24', '00:00:00:00:01:01', 's1', 'IOT:TempSensor')
    """
    from mininet.link import Link
    print(f"*** Dynamically adding IoT device: {name}")
    try:
        # Check if device already exists to avoid error
        if name in net.nameToNode:
            print(f"Device {name} already exists.")
            return

        # Get switch node
        switch = net.getNodeByName(switch_name) if isinstance(switch_name, str) else switch_name
        
        if not switch:
            print(f"Switch {switch_name} not found.")
            return

        # 1. Add host
        iot = net.addHost(name, ip=ip, mac=mac)
        if not iot:
            print(f"Error: Failed to create host {name}")
            return
            
        print(f"*** Host {name} created. Adding link to {switch.name} manually...")
        
        # 2. Add link manually (more reliable at runtime)
        link = Link(iot, switch)
        if not link:
            print(f"Error: Manual Link creation returned None")
            return
            
        # 3. Add link to net's records for cleanup later
        net.links.append(link)
            
        # 4. Configure interface
        iot.configDefault()
        
        # 5. Attach to switch port
        if hasattr(switch, 'attach'):
            switch.attach(link.intf2)
        
        print(f"*** Link added and connected to switch. Starting registration thread...")

        def _send_reg():
            time.sleep(2)
            print(f"*** Sending registration packet from {name}...")
            # Register device type + hostname via direct UDP to controller
            host_ip = ip.split('/')[0]
            # Include the device IP so the controller can register it as IoT by IP
            # (REGISTER:IOT:<ip>:<type>) — its MAC OUI may not be recognised.
            _send_to_controller(f"REGISTER:IOT:{host_ip}:{device_type}")
            _send_to_controller(f"REGISTER:NAME:{name}:{host_ip}")
            print(f"*** Registration packet sent for {name}")

        t = threading.Thread(target=_send_reg)
        t.daemon = True
        t.start()
        
    except Exception as e:
        print(f"Error adding/registering device {name}: {e}")
        import traceback
        traceback.print_exc()

def connect_iot_device(net, name, ip, mac, switch_name):
    """
    Simulates simply CONNECTING a device (Wired) without running any special script.
    Usage: py connect_iot_device(net, 'new1', '10.0.0.99/24', '00:00:00:00:00:99', 's1')
    """
    print(f"*** Connecting new IoT device: {name} (Passive Mode)")
    try:
        if name in net.nameToNode:
            print(f"Device {name} already exists.")
            return

        # Get switch
        if isinstance(switch_name, str):
            switch = net.getNodeByName(switch_name)
        else:
            switch = switch_name
        
        if not switch:
            print(f"Switch {switch_name} not found.")
            return

        # Add host
        iot = net.addHost(name, ip=ip, mac=mac)
        # Add link
        link = net.addLink(iot, switch)
        # Configure interface
        iot.configDefault()
        # Attach to switch port
        switch.attach(link.intf2)
        
        print(f"*** {name} connected to {switch.name}. Waiting for traffic (ARP/DHCP) to trigger discovery.")
        
    except Exception as e:
        print(f"Error connecting device {name}: {e}")

def ping_controller(net, host_name='h1', controller_ip=CONTROLLER_IP):
    """
    Test controller reachability from the topology VM (not from Mininet hosts).
    Mininet hosts on 10.0.0.x cannot reach 192.168.1.x directly.
    """
    import subprocess
    print(f"*** Pinging controller ({controller_ip}) from topology VM...")
    try:
        result = subprocess.run(
            ['ping', '-c', '3', controller_ip],
            capture_output=True, text=True, timeout=10
        )
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr)
    except Exception as e:
        print(f"Error: {e}")

def start_background_traffic(net):
    """
    Starts realistic background traffic (pings, HTTP requests, IoT heartbeats)
    to simulate real-world activity without triggering flood alerts.
    """
    print("*** Starting HTTP server on h2 (10.0.0.4)...")
    h2 = net.getNodeByName('h2')
    h2.cmd('python3 -m http.server 80 &')
    
    print("*** Starting iperf server on h2 (10.0.0.4) on port 5001...")
    h2.cmd('iperf -s -p 5001 &')
    
    time.sleep(1)
    
    print("*** Starting simulated web browsing on sta1 and sta2...")
    sta1 = net.getNodeByName('sta1')
    sta2 = net.getNodeByName('sta2')
    sta1.cmd('while true; do { curl -s --connect-timeout 2 -o /dev/null http://10.0.0.4/ || wget -q -O /dev/null --timeout=2 http://10.0.0.4/ ; } 2>/dev/null; sleep $((RANDOM % 8 + 3)); done &')
    sta2.cmd('while true; do { curl -s --connect-timeout 2 -o /dev/null http://10.0.0.4/ || wget -q -O /dev/null --timeout=2 http://10.0.0.4/ ; } 2>/dev/null; sleep $((RANDOM % 8 + 3)); done &')
    
    print("*** Starting periodic iperf traffic from sta1 to h2 on port 5001...")
    sta1.cmd('while true; do iperf -c 10.0.0.4 -p 5001 -t 2 > /dev/null; sleep $((RANDOM % 20 + 15)); done &')
    
    print("*** Starting low-frequency connectivity check on h1...")
    h1 = net.getNodeByName('h1')
    h1.cmd('while true; do ping -c 1 -W 1 10.0.0.1 > /dev/null; ping -c 1 -W 1 10.0.0.2 > /dev/null; sleep 10; done &')
    
    # Check if dynamic IoT devices exist and start their telemetry
    if 'TempSensor' in net.nameToNode:
        print("*** Starting realistic IoT telemetry on TempSensor (10.0.0.5)...")
        temp = net.nameToNode['TempSensor']
        # Frequent small sensor publishes to the server (HTTP GET w/ query -> bidirectional, gets a reply)
        temp.cmd('while true; do { curl -s --max-time 2 -o /dev/null "http://10.0.0.4/?temp=$((RANDOM%10+20))&hum=$((RANDOM%40+30))" || wget -q -O /dev/null --timeout=2 "http://10.0.0.4/?temp=$((RANDOM%10+20))&hum=$((RANDOM%40+30))" ; } 2>/dev/null; sleep $((RANDOM%4+3)); done &')
        # MQTT-style UDP publish (protocol variety, fire-and-forget)
        temp.cmd('while true; do echo "temp=$((RANDOM%10+20))" | nc -u -w1 10.0.0.4 8883; sleep $((RANDOM%3+4)); done &')
        # Periodic keepalive to the server (jittered so it is not perfectly robotic)
        temp.cmd('while true; do ping -c 1 -W 1 10.0.0.4 > /dev/null 2>&1; sleep $((RANDOM%6+12)); done &')
        
    if 'Cam' in net.nameToNode:
        print("*** Starting realistic IoT traffic on Cam (10.0.0.6)...")
        cam = net.nameToNode['Cam']
        # Video-stream-like upload bursts (iperf simulates sustained camera bandwidth)
        cam.cmd('while true; do iperf -c 10.0.0.4 -p 5001 -t 3 > /dev/null 2>&1; sleep $((RANDOM%15+15)); done &')
        # Periodic config/snapshot pulls from the server (HTTP GET -> bidirectional, larger transfer)
        cam.cmd('while true; do { curl -s --max-time 3 -o /dev/null http://10.0.0.4/ || wget -q -O /dev/null --timeout=2 http://10.0.0.4/ ; } 2>/dev/null; sleep $((RANDOM%10+10)); done &')
        # Control-plane heartbeat (MQTT-style TCP keepalive)
        cam.cmd('while true; do echo "ping" | nc -w1 10.0.0.4 1883; sleep $((RANDOM%3+3)); done &')

    print("*** Background traffic successfully started!")

def topology():
    net = Mininet_wifi(controller=RemoteController)
    
    print("*** Creating nodes")
    sta1 = net.addStation('sta1', mac='42:00:00:00:00:00',
                          ip='10.0.0.1/24', position='15,25,0')  
    sta2 = net.addStation('sta2', mac='42:00:00:00:01:00',
                          ip='10.0.0.2/24', position='25,25,0')  
    ap1 = net.addAccessPoint('ap1', mac='42:00:00:00:02:00',
                             ssid='ssid-ap1', mode='g', channel='1', 
                             position='20,30,0', range=50)
    h1 = net.addHost('h1', ip='10.0.0.3/24')  
    h2 = net.addHost('h2', ip='10.0.0.4/24')
    s1 = net.addSwitch('s1')
    c0 = net.addController('c0', controller=RemoteController, 
                           ip=CONTROLLER_IP, port=6633)
    
    print("*** Configuring WiFi nodes")
    net.configureWifiNodes()
    
    print("*** Creating links")
    net.addLink(ap1, s1)
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    
    print("*** Starting network")
    net.build()
    c0.start()
    s1.start([c0])
    ap1.start([c0])

    # Inject functions into net object so they are available to 'py' command
    net.register_iot_device = register_iot_device
    net.connect_iot_device = connect_iot_device
    net.ping_controller = ping_controller
    net.start_background_traffic = start_background_traffic

    # --- Detection Mode Toggle ---
    def detect_on(net):
        """Enable anomaly detection on the controller."""
        _send_to_controller('CONTROL:DETECT:ON')
        print("*** Detection mode: ON — attacks will be detected and blocked")

    def detect_off(net):
        """Disable anomaly detection on the controller."""
        _send_to_controller('CONTROL:DETECT:OFF')
        print("*** Detection mode: OFF — capture only, all labels = normal")

    net.detect_on = detect_on
    net.detect_off = detect_off

    # --- Attack Signalling (metadata + optional forced labels) ---
    def attack_start(net, tool='hping3', intensity='flood'):
        """Tell the controller an attack is starting (fills meta_attack_* columns).
        Call right before launching an attack tool. Audit metadata only — it does
        NOT change labels (labels come from Snort/DAI/rate-counters)."""
        _send_to_controller(f'ATTACK_START:{tool}:{intensity}')
        print(f"*** Attack metadata SET: tool={tool}, intensity={intensity}")

    def attack_stop(net):
        """Tell the controller the attack has stopped (clears meta_attack_*)."""
        _send_to_controller('ATTACK_STOP')
        print("*** Attack metadata CLEARED")

    def label_attacker(net, ip, attack_type):
        """Force every flow from ip to be labelled attack_type (ground-truth
        injection for stealthy/sub-threshold attacks). NOTE: labels ALL protocols
        from that IP, so only use it on a host that is sending just the attack.
        Clear with attack_type='clear'."""
        _send_to_controller(f'LABEL_OVERRIDE:{ip}:{attack_type}')
        print(f"*** Label override: {ip} -> {attack_type}")

    net.attack_start = attack_start
    net.attack_stop = attack_stop
    net.label_attacker = label_attacker

    # --- One-shot timed attack (handles ATTACK_START -> run -> ATTACK_STOP -> settle) ---
    def launch_attack(net, host, kind, target='10.0.0.4', duration=25, settle=15):
        """Run ONE labelled attack from `host` with timing handled automatically:
        send ATTACK_START, run the tool for `duration`s (timeout-bounded), send
        ATTACK_STOP, then block `settle`s so the detector clears before the next.
        kind in {icmp, syn, udp, cps, scan, arp}. Returns when fully done."""
        node = net.getNodeByName(host)
        if node is None:
            print(f"*** launch_attack: unknown host '{host}'"); return
        intf = node.defaultIntf()
        intfname = intf.name if intf is not None else f"{host}-eth0"
        specs = {
            'icmp': ('hping3', 'icmp-flood', f'timeout {duration} hping3 --icmp --flood {target}'),
            'syn':  ('hping3', 'syn-flood',  f'timeout {duration} hping3 -S --flood -p 80 {target}'),
            'udp':  ('hping3', 'udp-flood',  f'timeout {duration} hping3 --udp --flood -p 53 {target}'),
            'cps':  ('hping3', 'cps',        f'timeout {duration} hping3 --udp --flood -p ++1 {target}'),
            'scan': ('nmap',   'port-scan',  f'timeout {duration} nmap -sS -p 1-1000 {target}'),
            'arp':  ('arpspoof','arp-spoof', f'timeout {duration} arpspoof -i {intfname} -t {target} 10.0.0.3'),
        }
        if kind not in specs:
            print(f"*** launch_attack: kind must be one of {list(specs)}"); return
        tool, intensity, cmd = specs[kind]
        host_ip = node.IP()
        _send_to_controller(f'ATTACK_START:{tool}:{intensity}')
        print(f"*** [{host}] {kind} -> {target} for {duration}s (ATTACK_START sent)")
        node.cmd(cmd)
        _send_to_controller('ATTACK_STOP')
        # Let the controller flush + LABEL the attack's final window BEFORE we clear.
        # The flush runs every ~5 s. A fast attack — an nmap port scan finishes in
        # ~1-2 s — otherwise has its CLEAR + drain-cooldown applied before its window
        # is ever scored, so the controller's cooldown gate labels the whole scan
        # 'normal' (0 attack rows). Wait just over one flush window first. For floods
        # this 7 s is high-rate drain that labels as real attack, so it costs nothing.
        FLUSH_GRACE = 7
        time.sleep(FLUSH_GRACE)
        # Now release this source. The controller applies a short drain-suppression
        # cooldown to the cleared IP so the remaining post-stop backlog cannot
        # RE-CONFIRM the host — otherwise it would stay a confirmed attacker for the
        # rest of the session and mislabel its later traffic (esp. victim RST/SYN-ACK
        # back-scatter when targeted in a subsequent pair). In production the controller
        # keeps attackers locked in (admin-only UNBLOCK); this CLEAR is collection-only.
        _send_to_controller(f'CONTROL:CLEAR:{host_ip}')
        print(f"*** [{host}] {kind} done; released {host_ip}; settling before next attack")
        time.sleep(max(0, settle - FLUSH_GRACE))
        print(f"*** [{host}] {kind} ready for next")

    def wait(net, seconds):
        """Block the CLI for `seconds` (e.g. to let device baselines mature)."""
        print(f"*** waiting {seconds}s (baseline maturing / settling) ...")
        time.sleep(seconds)
        print("*** wait complete")

    # --- Whole-session attack automation (one command per session) ---
    # Default attacker->target pairs: diverse profiles (heavy/light/IoT) with
    # lateral targets (internal hosts, not just the server). Each pair becomes a
    # timed launch_attack with the settle in between.
    _SESSION_PAIRS = [
        ('sta1', '10.0.0.4'),         # heavy user -> server
        ('sta2', '10.0.0.4'),         # light user -> server
        ('h1',   '10.0.0.4'),         # wired host -> server
        ('Cam',  '10.0.0.4'),         # infected IoT -> server
        ('TempSensor', '10.0.0.3'),   # infected IoT -> lateral (internal host)
        ('sta1', '10.0.0.6'),         # lateral to IoT camera
        ('Cam',  '10.0.0.3'),         # infected IoT -> lateral
        ('h1',   '10.0.0.5'),         # lateral to IoT sensor
    ]

    def run_attack_session(net, kind, duration=None, settle=15, rounds=1, pairs=None):
        """Run a FULL labelled attack session for `kind` in ONE command.

        Runs several attacker->target pairs (diverse profiles incl. IoT, with
        lateral targets), each via launch_attack (timed: run + settle). Volumetric
        floods (icmp/syn/udp) default to a LONGER duration to beat the
        flow-collapse effect (a flood is ~1 flow/window, so longer run = more rows).
        Scans/CPS are already row-heavy, so they use the shorter default.

        kind in {icmp, syn, udp, cps, scan, arp}.
        Overrides: duration=<s>, settle=<s>, rounds=<n>, pairs=[('host','ip'),...].
        BLOCKS the CLI until the whole session finishes.
        """
        flood = kind in ('icmp', 'syn', 'udp')
        if duration is None:
            duration = 60 if flood else 25
        plist = pairs if pairs is not None else _SESSION_PAIRS
        total = len(plist) * rounds
        est_min = total * (duration + settle) / 60.0
        print(f"*** {kind.upper()} SESSION: {total} attacks x {duration}s run + {settle}s settle "
              f"(~{est_min:.0f} min). This BLOCKS the CLI until done — let it run.")
        n = 0
        for _ in range(rounds):
            for host, target in plist:
                n += 1
                print(f"*** [{n}/{total}] {kind} {host} -> {target}")
                launch_attack(net, host, kind, target, duration=duration, settle=settle)
        print(f"*** {kind.upper()} SESSION complete ({total} attacks). "
              f"Now: exit -> Ctrl-C -> rename dataset.csv -> validate_dataset.py")

    # --- High-yield TOP-UP collection (concurrent multi-target floods) ---
    # The thin classes (ICMP/SYN/UDP/ARP) are thin because a flood from one src
    # to one dst is a SINGLE flow key -> ONE row per 5 s window (flow collapse).
    # Row count scales with (concurrent flow keys) x (windows), NOT packet volume.
    # So each source floods ALL other hosts CONCURRENTLY (5 flow keys/source) for
    # a longer duration -> ~5x the rows. One source at a time keeps per-attacker
    # labels clean (the label-integrity invariant). Per-host CPU caps total pps,
    # so the controller load is ~the same as the old 1:1 floods — just more flows.
    _ALL_IPS = ['10.0.0.1', '10.0.0.2', '10.0.0.3',
                '10.0.0.4', '10.0.0.5', '10.0.0.6']
    _ATTACK_META = {
        'icmp': ('hping3',   'icmp-flood', 'ICMP Flood'),
        'syn':  ('hping3',   'syn-flood',  'SYN Flood'),
        'udp':  ('hping3',   'udp-flood',  'UDP Flood'),
        'cps':  ('hping3',   'cps',        'Control Plane Saturation'),
        'scan': ('nmap',     'port-scan',  'Port Scan'),
        'arp':  ('arpspoof', 'arp-spoof',  'ARP Spoofing'),
    }

    def _attack_cmd(kind, target, intfname, duration, rate):
        """One timeout-bounded attack command against a single target. rate='flood'
        -> hping3 --flood; else an inter-packet gap in microseconds (rate=200 ->
        -i u200 ~ 5000 pps) to bound load while staying above detection thresholds."""
        rl = '--flood' if rate == 'flood' else '-i u%d' % int(rate)
        return {
            'icmp': 'timeout %d hping3 --icmp %s %s' % (duration, rl, target),
            'syn':  'timeout %d hping3 -S %s -p 80 %s' % (duration, rl, target),
            'udp':  'timeout %d hping3 --udp %s -p 53 %s' % (duration, rl, target),
            'cps':  'timeout %d hping3 --udp %s -p ++1 %s' % (duration, rl, target),
            'scan': 'timeout %d nmap -sS -p 1-1000 %s' % (duration, target),
            'arp':  'timeout %d arpspoof -i %s -t %s 10.0.0.3' % (duration, intfname, target),
        }.get(kind)

    def launch_attack_multi(net, host, kind, duration=180, settle=15, rate='flood'):
        """One source attacks ALL other hosts concurrently for `duration`s, then
        ATTACK_STOP -> 7s flush-grace -> CONTROL:CLEAR this source -> settle."""
        node = net.getNodeByName(host)
        if node is None:
            print('*** launch_attack_multi: unknown host %s' % host); return
        if kind not in _ATTACK_META:
            print('*** launch_attack_multi: bad kind %s' % kind); return
        intf = node.defaultIntf()
        intfname = intf.name if intf is not None else '%s-eth0' % host
        tool, intensity, _ = _ATTACK_META[kind]
        host_ip = node.IP()
        targets = [ip for ip in _ALL_IPS if ip != host_ip]
        _send_to_controller('ATTACK_START:%s:%s' % (tool, intensity))
        print('*** [%s] %s -> %s concurrently for %ss (ATTACK_START sent)'
              % (host, kind, targets, duration))
        for t in targets:
            cmd = _attack_cmd(kind, t, intfname, duration, rate)
            if cmd:
                node.cmd(cmd + ' >/dev/null 2>&1 &')
        time.sleep(duration + 2)                       # tools self-terminate via `timeout`
        node.cmd('pkill -f %s 2>/dev/null' % tool)     # kill any straggler (sequential -> safe)
        _send_to_controller('ATTACK_STOP')
        time.sleep(7)                                  # flush-grace: label the final window before CLEAR
        _send_to_controller('CONTROL:CLEAR:%s' % host_ip)
        print('*** [%s] %s done; released %s; settling' % (host, kind, host_ip))
        time.sleep(max(0, settle - 7))

    def _bump_conntrack():
        """The floods overflow nf_conntrack (dmesg: 'table full, dropping packet'),
        silently dropping attack traffic. Raise the limit for the collection run."""
        import subprocess
        for key in ('net.netfilter.nf_conntrack_max=1048576',
                    'net.nf_conntrack_max=1048576'):
            try:
                subprocess.run(['sysctl', '-w', key], capture_output=True, timeout=5)
            except Exception:
                pass

    def run_topup_session(net, kind, duration=180, settle=15, baseline_secs=180,
                          rate='flood', sources=None, rotate_as=None):
        """High-yield single-class TOP-UP. Each source floods all other hosts
        concurrently (~5 flow keys/source) -> ~5x the rows of the old 1:1 pairs.
        Approx rows ~= 5 x (duration/5) x len(sources): duration=180 + 6 sources
        ~= 1000+ attack rows in ~20 min. kind in icmp/syn/udp/cps/scan/arp.

        Saves + auto-validates on the controller when rotate_as is given:
          py net.run_topup_session(net, 'syn', rotate_as='dataset_topup_syn.csv')
        """
        _bump_conntrack()
        # Wipe any confirmed-attacker / suspicion state left by the PREVIOUS session
        # (global CONTROL:CLEAR = no IP -> full reset, no cooldown). Without this, a
        # prior session's confirmed attacker (esp. the SYN session) keeps stamping its
        # benign same-protocol background traffic with that label in THIS session ->
        # the validator's "sticky-confirm" RATE BLEED (e.g. 100% SYN-Flood rows in a
        # UDP/scan/ARP session). The per-source clears after each attack don't cross
        # session boundaries, so reset globally at the session start.
        _send_to_controller('CONTROL:CLEAR')
        time.sleep(1)
        srcs = sources if sources is not None else ['sta1', 'sta2', 'h1', 'h2',
                                                    'TempSensor', 'Cam']
        expect = _ATTACK_META[kind][2]
        rows_est = 5 * (duration // 5) * len(srcs)
        print('*** TOP-UP %s: %d sources x 5 targets x %ss (~%d attack rows, ~%d min). '
              'BLOCKS the CLI — let it run.'
              % (kind.upper(), len(srcs), duration, rows_est,
                 int(len(srcs) * (duration + settle) / 60)))
        detect_off(net)
        wait(net, baseline_secs)             # mature device baselines
        detect_on(net)
        wait(net, 5)                         # DAI baseline freeze
        for s in srcs:
            launch_attack_multi(net, s, kind, duration=duration, settle=settle, rate=rate)
        detect_off(net)
        if rotate_as:
            _send_to_controller('CONTROL:ROTATE:%s:%s' % (rotate_as, expect))
            print('*** TOP-UP %s saved as %s — watch the controller log for PASS/ISSUES'
                  % (kind.upper(), rotate_as))
        print('*** TOP-UP %s complete.' % kind.upper())

    def run_full_topup(net, duration=180, baseline_secs=180, classes=None):
        """ONE-COMMAND automated TOP-UP of the row-thin attack classes. Walk away.

        Runs, back-to-back, a high-yield `run_topup_session` per class (each = every
        source floods all other hosts concurrently -> ~5x rows), saving + auto-validating
        each on the controller. Detection is ON only to LABEL (ML forced OFF, no blocks).

        Defaults to the thin classes: udp (re-collect, was ISSUES), icmp, syn, arp(longer).
        Override e.g. classes=[('udp','dataset_session4_udp.csv'),('scan','dataset_topup_scan.csv')].

          py net.run_full_topup(net)           # ~1-1.5 h, walk away
          py net.run_full_topup(net, duration=120)   # quicker / fewer rows
        """
        sessions = classes if classes is not None else [
            ('udp',  'dataset_session4_udp.csv'),   # re-collect (previously ISSUES)
            ('icmp', 'dataset_topup_icmp.csv'),
            ('syn',  'dataset_topup_syn.csv'),
            ('arp',  'dataset_topup_arp.csv'),
        ]
        est = sum((300 if k == 'arp' else duration) for k, _ in sessions)
        print('*** FULL TOP-UP — %d thin-class sessions, FULLY AUTOMATED. Walk away (~%d min).'
              % (len(sessions), int(len(sessions) * (baseline_secs + 30) / 60 + est * 6 / 60)))
        _send_to_controller('CONTROL:ML:OFF')          # never block during collection
        start_background_traffic(net)
        wait(net, baseline_secs)                       # initial warm-up so device baselines mature
        for i, (kind, fname) in enumerate(sessions, start=1):
            dur = 300 if kind == 'arp' else duration   # ARP is low-volume -> run it longer
            print('*** [%d/%d] TOP-UP %s -> %s' % (i, len(sessions), kind.upper(), fname))
            run_topup_session(net, kind, duration=dur, baseline_secs=baseline_secs,
                              rotate_as=fname)
        print('*** FULL TOP-UP complete — review the controller log for each PASS/ISSUES, '
              'then merge with dataset_merge.py into the v3 master.')

    def run_full_collection_hy(net, normal_secs=600, duration=180, baseline_secs=180):
        """ONE-COMMAND HIGH-YIELD full collection: 1 normal + 6 attack sessions
        (icmp, syn, udp, scan, arp, cps), each using the concurrent multi-target floods
        (~5x rows on the thin flood classes), each saved + auto-validated on the
        controller. Detection ON only LABELS (ML forced OFF, no blocks). Walk away.

        This is the all-types version of run_full_topup; use it for a fresh full dataset
        you will MERGE into the existing master. Merge the 7 files afterwards.

          py net.run_full_collection_hy(net)                  # ~2-2.5 h
          py net.run_full_collection_hy(net, duration=120)    # quicker / fewer rows
        """
        _send_to_controller('CONTROL:ML:OFF')          # never block during collection
        start_background_traffic(net)
        detect_off(net)
        _send_to_controller('CONTROL:ROTATE:_discard.csv')   # drop setup/pingall noise
        wait(net, 3)

        print('*** [1/7] NORMAL — %ds of pure background' % normal_secs)
        wait(net, normal_secs)
        _send_to_controller('CONTROL:ROTATE:dataset_session1_normal.csv')
        wait(net, 5)

        attacks = [('icmp', 'dataset_session2_icmp.csv'),
                   ('syn',  'dataset_session3_syn.csv'),
                   ('udp',  'dataset_session4_udp.csv'),
                   ('scan', 'dataset_session5_portscan.csv'),
                   ('arp',  'dataset_session6_arpspoof.csv'),
                   ('cps',  'dataset_session7_cps.csv')]
        for i, (kind, fname) in enumerate(attacks, start=2):
            dur = 300 if kind == 'arp' else duration   # ARP is low-volume -> run longer
            print('*** [%d/7] %s -> %s' % (i, kind.upper(), fname))
            run_topup_session(net, kind, duration=dur, baseline_secs=baseline_secs,
                              rotate_as=fname)
        print('*** FULL HIGH-YIELD COLLECTION complete — 7 sessions saved + validated. '
              'Merge into the bigger master with dataset_merge.py.')

    def run_full_attack_demo(net, duration=40, settle=25, baseline_secs=150,
                             threshold=0.80, classes=None):
        """WALK-AWAY LIVE DEMO — PROVES the system detects AND blocks (this is NOT a
        dataset run). Unlike run_full_collection_hy (which forces ML OFF and never
        blocks), this ARMS THE FULL STACK (DETECT ON + ML AUTHORIZE) so Snort +
        rate/DAI + RF + AE all score and block, then launches each attack type once
        from sta1 -> the server. Every block prints an 'ATTACKER BLOCKED' box.

        Walk away, then collect the proof from the controller side:
            grep -E "ATTACKER BLOCKED|SNORT] BLOCKED|[ML]|[AE]" controller_run.log
            curl -s http://127.0.0.1:8081/ips/blocked | python3 -m json.tool
            + the dashboard timeline / blocked-hosts table.

            py net.run_full_attack_demo(net)              # ~10 min, walk away
            py net.run_full_attack_demo(net, duration=60) # longer attacks
        """
        import random
        classes = classes or ['syn', 'icmp', 'udp', 'scan', 'cps', 'arp']
        # Pool of possible attackers (the server h2/10.0.0.4 is the TARGET, not an attacker).
        attacker_pool = ['sta1', 'sta2', 'h1', 'Cam', 'TempSensor']
        eta = int((baseline_secs + len(classes) * (duration + settle + 9)) / 60) + 1
        print('*** LIVE BLOCK DEMO — full stack (DETECT ON + ML AUTHORIZE:%.2f), %d attacks '
              'from RANDOM attackers. Walk away (~%d min). This BLOCKS — NOT a clean dataset run.'
              % (threshold, len(classes), eta))
        # 1) Warm up FIRST so device baselines mature BEFORE blocking is armed —
        #    otherwise the AE flags/locks legitimate hosts the instant AUTHORIZE is on.
        _send_to_controller('CONTROL:ML:OFF')
        detect_off(net)
        start_background_traffic(net)
        wait(net, baseline_secs)
        # 2) Arm the full stack (all four tiers now score; RF/AE/Snort block).
        detect_on(net)
        _send_to_controller('CONTROL:ML:AUTHORIZE:%.2f' % threshold)
        time.sleep(2)
        # 3) One attack per type. CLEAR between attacks so a still-active block from the
        #    previous type does not pre-empt the next (each type gets a clean shot).
        for i, kind in enumerate(classes, start=1):
            _send_to_controller('CONTROL:CLEAR')
            time.sleep(2)
            attacker = random.choice(attacker_pool)   # random attacker per attack type
            print('*** [%d/%d] DEMO %s: %s -> 10.0.0.4  (expect ATTACKER BLOCKED in the log)'
                  % (i, len(classes), kind.upper(), attacker))
            launch_attack(net, attacker, kind, target='10.0.0.4',
                          duration=duration, settle=settle)
        _send_to_controller('CONTROL:CLEAR')
        print('*** LIVE BLOCK DEMO complete. PROOF: grep "ATTACKER BLOCKED" controller_run.log ; '
              'curl -s http://127.0.0.1:8081/ips/blocked ; and the dashboard.')

    def expose_service(net, host='h2', ports='8080', host_port=80,
                       protos=('tcp',), ext_iface=None, gw_ip='10.0.0.254'):
        """Route EXTERNAL LAN traffic INTO the SDN so an outsider (e.g. a Windows box)
        transits s1 -> packet_in -> ALL 4 tiers (Snort + rate/DAI + RF + AE). The
        controller then sees the REAL external source IP and blocks it with an OpenFlow
        DROP — the full-stack 'attack from outside the environment' proof (vs PART 12's
        management-plane hit, which only Snort+iptables catch).

        Mechanism: add a gateway port on s1 in the ROOT namespace (gw_ip on 10.0.0.0/24)
        and DNAT  <this-VM-ip>:<ports>  ->  <host>. `ports` is a single port ('8080' ->
        host:host_port) or a RANGE ('1-1000', dport preserved) so an external PORT SCAN
        also transits the SDN.

          py net.expose_service(net)                        # h2:80 as <vm-ip>:8080  (SYN flood test)
          py net.expose_service(net, ports='1-1000')        # forward a range (external port scan)
          py net.expose_service(net, ports='8053', host_port=53, protos=('udp',))  # UDP flood
        Tear down with: py net.unexpose_service(net)
        """
        import subprocess as _sp
        h = net.get(host); host_ip = h.IP()
        if ext_iface is None:
            ext_iface = (_sp.getoutput("ip route show default | awk '{print $5; exit}'").strip()
                         or 'ens33')
        vm_ip = _sp.getoutput("ip -4 addr show %s | awk '/inet /{print $2}' | cut -d/ -f1"
                              % ext_iface).strip()
        dport = ports.replace('-', ':'); is_range = (':' in dport)
        dest = host_ip if is_range else ('%s:%d' % (host_ip, host_port))

        def sh(c): _sp.run(c, shell=True)
        # 1) gateway interface for the ROOT namespace ON s1 (routes into 10.0.0.0/24)
        sh("ovs-vsctl --may-exist add-port s1 sdn-gw -- set interface sdn-gw type=internal")
        sh("ip addr flush dev sdn-gw 2>/dev/null; ip addr add %s/24 dev sdn-gw; "
           "ip link set sdn-gw up" % gw_ip)
        sh("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
        # 2) DNAT external :<ports> -> host, and allow forwarding into the SDN
        for p in protos:
            sh("iptables -t nat -A PREROUTING -i %s -p %s --dport %s -j DNAT --to-destination %s"
               % (ext_iface, p, dport, dest))
            sh("iptables -A FORWARD -p %s -d %s -j ACCEPT" % (p, host_ip))
        # 3) return path: the target host sends replies back via the root gateway
        h.cmd("ip route replace default via %s" % gw_ip)
        p0 = ports.split('-')[0]
        print("*** EXPOSED %s (%s) to the LAN as %s:%s [%s] — external traffic now transits s1 "
              "(packet_in -> all 4 tiers)." % (host, host_ip, vm_ip, ports, ','.join(protos)))
        print("*** Attack from an EXTERNAL host (Windows) at %s :" % vm_ip)
        print("      nping --tcp --flags syn -p %s --rate 3000 -c 30000 %s   # SYN flood -> RF/AE/Snort"
              % (p0, vm_ip))
        print("      nmap  -sS -p %s %s                        # port scan (use a RANGE) -> port_scan"
              % (ports, vm_ip))
        print("      (WSL) sudo hping3 -S --flood -p %s %s" % (p0, vm_ip))
        print("*** Expect ATTACKER BLOCKED with the REAL external src IP (OpenFlow DROP). "
              "Teardown: py net.unexpose_service(net)")

    def unexpose_service(net):
        """Remove the external-exposure gateway/NAT added by expose_service."""
        import subprocess as _sp
        def sh(c): _sp.run(c, shell=True)
        sh("iptables -t nat -F PREROUTING"); sh("iptables -F FORWARD")
        sh("ovs-vsctl --if-exists del-port s1 sdn-gw")
        print("*** Un-exposed: removed sdn-gw + DNAT/FORWARD rules.")

    def run_full_collection(net, normal_secs=600, baseline_secs=300):
        """FULLY AUTOMATED 7-session capture in ONE command. Walk away (~1.5-2 h).

        Runs: 1 normal session + 6 attack sessions (icmp, syn, udp, scan, arp, cps).
        Between sessions it tells the controller to SAVE the session's dataset.csv
        under its own filename and auto-VALIDATE it (watch the controller log for
        'PASS'/'ISSUES' per session). Detection is ON only during attacks (labels,
        no block); ML blocking is forced OFF for the whole run. Each session's
        attack uses run_attack_session (8 diverse source->target pairs).

        After it finishes, merge the 7 files on the controller:
          python3 dataset_merge.py dataset_session1_normal.csv ... \\
                  dataset_session7_cps.csv --output dataset_v2_master_new.csv
        """
        attack_sessions = [
            ('icmp', 'dataset_session2_icmp.csv',     'ICMP Flood'),
            ('syn',  'dataset_session3_syn.csv',      'SYN Flood'),
            ('udp',  'dataset_session4_udp.csv',      'UDP Flood'),
            ('scan', 'dataset_session5_portscan.csv', 'Port Scan'),
            ('arp',  'dataset_session6_arpspoof.csv', 'ARP Spoofing'),
            ('cps',  'dataset_session7_cps.csv',      'Control Plane Saturation'),
        ]
        print("*** FULL COLLECTION — 7 sessions, FULLY AUTOMATED. Walk away (~1.5-2 h).")
        _send_to_controller('CONTROL:ML:OFF')          # never block during collection
        start_background_traffic(net)
        # discard pre-collection traffic (setup/pingall) so session 1 starts clean
        detect_off(net)
        _send_to_controller('CONTROL:ROTATE:_discard.csv')
        wait(net, 3)

        # --- Session 1: NORMAL (background only) ---
        print(f"*** [1/7] NORMAL — {normal_secs}s of pure background")
        wait(net, normal_secs)
        _send_to_controller('CONTROL:ROTATE:dataset_session1_normal.csv')
        wait(net, 5)

        # --- Sessions 2-7: one attack type each ---
        for i, (kind, fname, expect) in enumerate(attack_sessions, start=2):
            print(f"*** [{i}/7] {expect} — baseline {baseline_secs}s, then attack")
            detect_off(net)
            wait(net, baseline_secs)                    # mature device baselines
            detect_on(net)
            wait(net, 5)                                # DAI baseline freeze
            run_attack_session(net, kind)               # 8 diverse pairs (blocks)
            detect_off(net)
            _send_to_controller(f'CONTROL:ROTATE:{fname}:{expect}')
            wait(net, 5)

        print("*** FULL COLLECTION complete — 7 sessions saved + validated on the controller.")
        print("*** Review the controller log for each session's PASS/ISSUES, then merge with "
              "dataset_merge.py and append to dataset_v2_master.csv.")

    net.launch_attack = launch_attack
    net.launch_attack_multi = launch_attack_multi
    net.wait = wait
    net.run_attack_session = run_attack_session
    net.run_topup_session = run_topup_session
    net.run_full_topup = run_full_topup
    net.run_full_collection_hy = run_full_collection_hy
    net.run_full_collection = run_full_collection
    net.run_full_attack_demo = run_full_attack_demo
    net.expose_service = expose_service
    net.unexpose_service = unexpose_service

    # --- Send hostname registrations to the controller ---
    # Sends REGISTER:NAME:hostname:ip directly to controller over physical network
    def _register_hostnames():
        time.sleep(3)  # Wait for switch to connect to controller
        all_hosts = [sta1, sta2, h1, h2]
        for host in all_hosts:
            name = host.name
            host_ip = host.IP() if hasattr(host, 'IP') else host.params.get('ip', '').split('/')[0]
            _send_to_controller(f"REGISTER:NAME:{name}:{host_ip}")
            print(f"*** Hostname registered: {name} ({host_ip})")
        print("*** All hostnames registered with controller")

    reg_thread = threading.Thread(target=_register_hostnames)
    reg_thread.daemon = True
    reg_thread.start()

    print("*** Registration: py net.register_iot_device(net, 'iot1', '10.0.0.5/24', '00:00...', 's1', 'IOT:Type')")
    print("*** Detection commands: py net.detect_on(net)  /  py net.detect_off(net)")
    print("*** Attack signalling: py net.attack_start(net,'hping3','flood')  /  py net.attack_stop(net)")
    print("*** One-command attack session: py net.run_attack_session(net,'icmp')  (kinds: icmp syn udp cps scan arp)")
    print("*** HIGH-YIELD top-up (one class): py net.run_topup_session(net,'syn',rotate_as='dataset_topup_syn.csv')")
    print("*** ONE-COMMAND AUTOMATED TOP-UP (thin classes): py net.run_full_topup(net)  (walk away; auto-saves + validates each)")
    print("*** HIGH-YIELD full collection (all types, good row counts): py net.run_full_collection_hy(net)  (walk away; auto-saves + validates each)")
    print("*** LIVE BLOCK DEMO (proves detection+blocking, NOT a dataset): py net.run_full_attack_demo(net)  (walk away ~10 min; arms AUTHORIZE, blocks each attack)")
    print("*** EXTERNAL attack into the SDN (outsider hits all 4 tiers): py net.expose_service(net)  then attack <vm-ip>:8080 from Windows; teardown: py net.unexpose_service(net)")
    print("*** FULLY AUTOMATED 7-session capture (sequential): py net.run_full_collection(net)  (walk away ~1.5-2 h; auto-saves + validates each)")

    # --- HANDS-FREE recollection: AUTO_COLLECT=1 runs the whole high-yield capture
    #     unattended (no CLI typing) so you can work on the t530 in parallel.
    #     Env knobs (all optional):
    #       AUTO_COLLECT=1            enable the hook (default off -> normal CLI)
    #       AUTO_COLLECT_MODE=full    'full' = run_full_collection_hy (all 7, default)
    #                                 'topup' = run_full_topup (thin classes only)
    #       AUTO_COLLECT_DURATION=180 per-attack flood seconds
    #       AUTO_COLLECT_NORMAL=600   normal-session seconds (full mode only)
    #       AUTO_REGISTER_IOT=1       auto-register TempSensor+Cam (the 5th/6th flood
    #                                 sources -> ~50% more attack rows). Default on.
    if _os.environ.get('AUTO_COLLECT', '0') == '1':
        _mode = _os.environ.get('AUTO_COLLECT_MODE', 'full').strip().lower()
        _dur = int(_os.environ.get('AUTO_COLLECT_DURATION', '180'))
        _normal = int(_os.environ.get('AUTO_COLLECT_NORMAL', '600'))
        if _os.environ.get('AUTO_REGISTER_IOT', '1') == '1':
            print("*** AUTO_COLLECT: registering IoT sources TempSensor + Cam (richer rows)")
            net.register_iot_device(net, 'TempSensor', '10.0.0.5/24',
                                    '00:00:00:00:00:05', 's1', 'IOT:TempSensor')
            net.register_iot_device(net, 'Cam', '10.0.0.6/24',
                                    '00:00:00:00:00:06', 's1', 'IOT:Camera')
            time.sleep(10)   # let the links come up + registrations reach the controller
        print("*** AUTO_COLLECT: starting UNATTENDED %s collection (walk away) ***" % _mode)
        try:
            if _mode == 'topup':
                net.run_full_topup(net, duration=_dur)
            else:
                net.run_full_collection_hy(net, normal_secs=_normal, duration=_dur)
            print("*** AUTO_COLLECT: DONE — review the controller log for per-session "
                  "PASS/ISSUES, then merge with dataset_merge.py. Dropping to CLI. ***")
        except Exception as _e:
            print("*** AUTO_COLLECT: aborted with error: %s — dropping to CLI ***" % _e)

    print("*** Running CLI")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()