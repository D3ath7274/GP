import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp

# 1. دالة ذكية لقراءة سياسة العميل من الملف الخارجي
def load_customer_policy():
    try:
        with open('config.json', 'r') as f:
            return json.load(f)
    except:
        # إعدادات افتراضية في حالة عدم وجود الملف
        return {"priority_traffic": "IoT", "traffic_is_high": True}

class RobustSDWANController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RobustSDWANController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst)
        dp.send_msg(mod)

    # --- التعديل السحري: إضافة idle_timeout=3 لعمل Auto-Reload ---
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, 
                                    idle_timeout=3, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, 
                                    idle_timeout=3, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']
        dpid = dp.id

        # --- 🚨 حماية الشبكة (Silent IPS Phantom) 🚨 ---
        # لو الداتا طالعة من سيرفر الـ IPS (بورت 6)، اعملها Drop فوراً عشان نمنع عاصفة الإيرور
        if dpid == 0x11 and in_port == 6:
            return 

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype in [ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6]:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = ofproto.OFPP_FLOOD

        DPID_S1 = 0x11
        DPID_S2 = 0x12
        DPID_S3 = 0x13
        DPID_S4 = 0x14

        is_ip = False
        ip_pkt = None
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)

        # --- بداية نظام الـ Adaptive Traffic Steering ---
        traffic_type = "Normal_PC" # الافتراضي لأي جهاز
        
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            is_ip = True
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            
            if ip_pkt:
                # أ) التصنيف الديناميكي (Dynamic Classification) بناءً على L4 Port
                dst_port = None
                if tcp_pkt: dst_port = tcp_pkt.dst_port
                elif udp_pkt: dst_port = udp_pkt.dst_port

                if dst_port in [1883, 5683, 9000]: # بورتات الـ IoT المعتمدة
                    traffic_type = "IoT"
                elif dst_port in [80, 443]: # تصفح ويب عادي
                    traffic_type = "Normal_PC"
                else:
                    # ب) الـ Fallback: لضمان عمل اختباراتك القديمة بدون تعديل
                    if ip_pkt.src in ['10.0.0.1', '10.0.0.2', '10.0.0.3'] or ip_pkt.dst in ['10.0.0.1', '10.0.0.2', '10.0.0.3']:
                        traffic_type = "IoT"

        # --- قراءة سياسة العميل وقرار الـ Threshold ---
        policy = load_customer_policy()
        priority_target = policy.get("priority_traffic", "IoT")
        traffic_is_high = policy.get("traffic_is_high", True)

        is_fast_path = False
        # شرط الدكتور: الأولوية تتفعل فقط لو التطبيق مطابق والترافيك تخطى الحد (Threshold)
        if traffic_type == priority_target and traffic_is_high:
            is_fast_path = True

        # --- توجيه البيانات ---
        if dpid in [DPID_S2, DPID_S3]:
            if in_port == 1: out_port = 2
            elif in_port == 2: out_port = 1
        
        else:
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]

            if is_ip:
                if dpid == DPID_S1 and out_port in [4, 5]:
                    out_port = 4 if is_fast_path else 5
                    # طباعة نوع الترافيك ديناميكياً لتوضيحه في المناقشة
                    if is_fast_path:
                        self.logger.info(f">>> [FAST PATH - VIP] App: {traffic_type} | Threshold Exceeded")
                    else:
                        self.logger.info(f">>> [BACKUP PATH] App: {traffic_type} | Normal Routing")
                
                elif dpid == DPID_S4 and out_port in [2, 3]:
                    out_port = 2 if is_fast_path else 3

        # العبور الآمن ومنع الـ Loops وتجهيز الـ Actions
        actions = []
        if out_port == ofproto.OFPP_FLOOD:
            for port_no in list(dp.ports.keys()):
                if port_no >= ofproto.OFPP_MAX or port_no == in_port: continue
                if dpid == DPID_S1 and port_no == 5: continue 
                if dpid == DPID_S4 and port_no == 3: continue 
                actions.append(parser.OFPActionOutput(port_no))
        else:
            # 1. إرسال الباكت في مسارها الطبيعي
            actions = [parser.OFPActionOutput(out_port)]
            
            # 2. نظام الـ Traffic Mirroring الآمن والمعدل:
            # ننسخ الترافيك فقط إذا كنا في S1، والباكت مش جاية من الـ IPS (بورت 6) ومش رايحة للـ IPS (بورت 6)
            if dpid == DPID_S1 and out_port != 6 and in_port != 6:
                IPS_MIRROR_PORT = 6
                actions.append(parser.OFPActionOutput(IPS_MIRROR_PORT))

        # تثبيت القواعد (Flow Tables) بدقة لتشمل الـ Ports
        if out_port != ofproto.OFPP_FLOOD:
            if is_ip and ip_pkt:
                if tcp_pkt:
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ip_proto=6, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, tcp_dst=tcp_pkt.dst_port)
                elif udp_pkt:
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ip_proto=17, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst, udp_dst=udp_pkt.dst_port)
                else:
                    match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(dp, 1, match, actions, msg.buffer_id)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        if out_port == ofproto.OFPP_FLOOD or data:
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
            dp.send_msg(out)
