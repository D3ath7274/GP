from mininet.node import RemoteController
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
import time
import sys
import os
import threading
import socket as _socket

# Add Controller directory to path for shared_secret import
_controller_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'Controller')
if os.path.isdir(_controller_dir):
    sys.path.insert(0, _controller_dir)
try:
    from shared_secret import sign_command
except ImportError:
    # Fallback: if shared_secret is not available, send unsigned (backward compat)
    print("*** WARNING: shared_secret.py not found — commands will be sent UNSIGNED")
    sign_command = None

# Controller physical IP (used for direct UDP commands)
CONTROLLER_IP = '192.168.1.19'
CONTROLLER_CMD_PORT = 9999

def _send_to_controller(msg):
    """Send a signed UDP command directly to the controller over the physical network.
    Commands are authenticated with HMAC-SHA256 to prevent forgery (Fix #1)."""
    try:
        # Sign the command before sending
        if sign_command is not None:
            signed_msg = sign_command(msg)
        else:
            signed_msg = msg  # Fallback: unsigned (development only)
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.sendto(signed_msg.encode(), (CONTROLLER_IP, CONTROLLER_CMD_PORT))
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