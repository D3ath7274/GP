from mininet.node import RemoteController
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI

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
                           ip='192.168.1.101', port=6633)
    
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
    
    print("*** Running CLI")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()