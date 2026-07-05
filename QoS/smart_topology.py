from mininet.node import RemoteController
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mininet.link import TCLink

CONTROLLER_IP = '192.168.1.7'

def topology():
    # التصحيح: إزالة link=TCLink من التعريف العام لحماية أجهزة الوايرلس
    net = Mininet_wifi(controller=RemoteController)

    print("*** Creating nodes")
    # ===== IoT devices (Fast Path) =====
    sta1 = net.addStation('sta1', ip='10.0.0.1/24', position='15,25,0')
    sta2 = net.addStation('sta2', ip='10.0.0.2/24', position='25,25,0')

    # ===== Normal devices (Backup Path) =====
    sta3 = net.addStation('sta3', ip='10.0.0.5/24', position='20,20,0')
    h3 = net.addHost('h3', ip='10.0.0.6/24')

    # التعديل الأول: تغيير mode لـ 'n' عشان يسمح بسرعات عالية تعدي الـ 100 ميجا
    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mode='g', channel='1', position='20,30,0', range=100, failMode='standalone')

    # ===== Hosts =====
    h1 = net.addHost('h1', ip='10.0.0.3/24')
    h2 = net.addHost('h2', ip='10.0.0.4/24')
    
    # إضافة سيرفر الـ IPS (الخاص بتحليل الترافيك)
    ips_server = net.addHost('ips', ip='10.0.0.99/24')

    # ===== SD-WAN switches (With fixed DPIDs) =====
    s1 = net.addSwitch('s1', dpid='11')
    s2 = net.addSwitch('s2', dpid='12')
    s3 = net.addSwitch('s3', dpid='13')
    s4 = net.addSwitch('s4', dpid='14')

    c0 = net.addController('c0', controller=RemoteController, ip=CONTROLLER_IP, port=6653)

    print("*** Configuring WiFi nodes")
    net.configureWifiNodes()

    print("*** Creating links")
    # التعديل الثاني: فتح سعة الكابلات الطرفية لـ 1 جيجا (1000) عشان متخنقش الشبكة
    net.addLink(ap1, s1, port2=1, cls=TCLink, bw=1000)
    net.addLink(h1, s1, port2=2, cls=TCLink, bw=1000)
    net.addLink(h3, s1, port2=3, cls=TCLink, bw=1000)
    
    # سيرفر الـ IPS (بورت 6 إجباري)
    net.addLink(ips_server, s1, port2=6, cls=TCLink, bw=1000)

    # s4 connection
    net.addLink(h2, s4, cls=TCLink, bw=1000)

    # ===== SD-WAN PATH 1 (FAST) =====
    # إجبار المسار السريع على بورت 4 في s1
    net.addLink(s1, s2, port1=4, cls=TCLink, bw=100, delay='2ms') 
    net.addLink(s2, s4, cls=TCLink, bw=100, delay='2ms') 

    # ===== SD-WAN PATH 2 (BACKUP) =====
    # إجبار المسار البطيء على بورت 5 في s1
    net.addLink(s1, s3, port1=5, cls=TCLink, bw=50, delay='15ms') 
    net.addLink(s3, s4, cls=TCLink, bw=50, delay='15ms') 

    print("*** Starting network")
    net.staticArp()
    net.build()
    c0.start()

    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    s4.start([c0])
    ap1.start([c0])

    print("*** Running CLI")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()
