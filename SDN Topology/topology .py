from mininet.node import RemoteController
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
import time
import threading

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
        # Using Link class directly avoids some net.addLink topology-build-time checks
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
            msg = f"REGISTER:{device_type}"
            cmd = f"python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'{msg}', ('10.0.0.254', 9999))\""
            iot.cmd(cmd)
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
        # We do NOT send the register packet here.
        # The user can trigger traffic manually or wait for natural network chatter (IPv6 DAD, etc.)
        # Or just ping the gateway: iot.cmd('ping -c1 10.0.0.1')
        
    except Exception as e:
        print(f"Error connecting device {name}: {e}")

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
                           ip='192.168.1.11', port=6633)  # Controller machine
    
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

    print(f"*** Registration function available: py net.register_iot_device(net, 'biot1', '10.0.0.5/24', '00:00...', 's1', 'IOT:Type')")
    print(f"*** Connection function available (Passive): py net.connect_iot_device(net, 'new1', '10.0.0.99/24', '00:00...99', 's1')")
    
    # Inject functions into net object so they are available to 'py' command
    net.register_iot_device = register_iot_device
    net.connect_iot_device = connect_iot_device

    # --- Send hostname registrations to the controller ---
    # Each host sends REGISTER:NAME:<hostname> so the controller can
    # map IP → device name for attack logs.
    def _register_hostnames():
        time.sleep(3)  # Wait for switch to connect to controller
        all_hosts = [sta1, sta2, h1, h2]
        for host in all_hosts:
            name = host.name
            msg = f"REGISTER:NAME:{name}"
            cmd = f"python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'{msg}', ('10.0.0.254', 9999))\""
            host.cmd(cmd)
            print(f"*** Hostname registered: {name}")
        print("*** All hostnames registered with controller")

    reg_thread = threading.Thread(target=_register_hostnames)
    reg_thread.daemon = True
    reg_thread.start()

    print("*** Running CLI")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()