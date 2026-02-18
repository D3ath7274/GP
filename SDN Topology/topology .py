from mininet.node import RemoteController
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
import time
import threading

def register_iot_device(net, name, ip, mac, switch_name, device_type):
    """
    Dynamically adds an IoT device and registers it with the controller.
    Usage in CLI: py register_iot_device(net, 'iot1', '10.0.0.5/24', '00:00:00:00:01:01', 's1', 'IOT:TempSensor')
    """
    print(f"*** Dynamically adding IoT device: {name}")
    try:
        # Check if device already exists to avoid error
        if name in net.nameToNode:
            print(f"Device {name} already exists.")
            return

        # Get switch node (by name if string provided)
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
        
        # Allow some time for link to come up and efficient ARP/Controller discovery
        # We spawn a thread for the registration packet so we don't block the CLI if called from there?
        # No, better to block slightly or just wait.
        # But if called from CLI 'py ...', sleep might block CLI.
        # Let's use a small delay or a thread.
        def _send_reg():
            time.sleep(2)
            print(f"*** Sending registration packet from {name}...")
            # specific UDP packet to port 9999
            # Payload: REGISTER:IOT:<Type> or REGISTER:GATEWAY:<Info>
            msg = f"REGISTER:{device_type}"
            # Using python to send packet as 'nc' might not be available
            # Sending to a broadcast-like IP or the gateway IP to ensure it reaches the switch
            cmd = f"python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'{msg}', ('10.0.0.254', 9999))\""
            iot.cmd(cmd)
            print(f"*** Registration packet sent for {name}")

        t = threading.Thread(target=_send_reg)
        t.start()
        
    except Exception as e:
        print(f"Error adding/registering device {name}: {e}")

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

    print(f"*** Registration function available: py register_iot_device(net, 'biot1', '10.0.0.5/24', '00:00...', s1, 'IOT:Type')")
    print(f"*** Connection function available (Passive): py connect_iot_device(net, 'new1', '10.0.0.99/24', '00:00...99', 's1')")
    
    print("*** Running CLI")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()