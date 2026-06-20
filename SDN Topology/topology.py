from mininet.node import RemoteController
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
import time
import threading
import socket as _socket

# Controller physical IP (used for direct UDP commands)
CONTROLLER_IP = '192.168.1.19'
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
            _send_to_controller(f"REGISTER:IOT:{device_type}")
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
    sta1.cmd('while true; do curl -s --connect-timeout 2 http://10.0.0.4/ > /dev/null; sleep $((RANDOM % 8 + 3)); done &')
    sta2.cmd('while true; do curl -s --connect-timeout 2 http://10.0.0.4/ > /dev/null; sleep $((RANDOM % 8 + 3)); done &')
    
    print("*** Starting periodic iperf traffic from sta1 to h2 on port 5001...")
    sta1.cmd('while true; do iperf -c 10.0.0.4 -p 5001 -t 2 > /dev/null; sleep $((RANDOM % 20 + 15)); done &')
    
    print("*** Starting low-frequency connectivity check on h1...")
    h1 = net.getNodeByName('h1')
    h1.cmd('while true; do ping -c 1 -W 1 10.0.0.1 > /dev/null; ping -c 1 -W 1 10.0.0.2 > /dev/null; sleep 10; done &')
    
    # Check if dynamic IoT devices exist and start their telemetry
    if 'TempSensor' in net.nameToNode:
        print("*** Starting UDP telemetry on TempSensor...")
        temp = net.nameToNode['TempSensor']
        temp.cmd('while true; do echo "temp=$((RANDOM % 10 + 20))" | nc -u -w1 10.0.0.4 8883; sleep 5; done &')
        
    if 'Cam' in net.nameToNode:
        print("*** Starting TCP heartbeats on Cam...")
        cam = net.nameToNode['Cam']
        cam.cmd('while true; do echo "ping" | nc -w1 10.0.0.4 1883; sleep 4; done &')

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
    print("*** Running CLI")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()