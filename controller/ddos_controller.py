# controller/ddos_controller.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
import pandas as pd
import os
import joblib
from collections import defaultdict
import time
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp


class DDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

        # --- Bagian Monitoring & Pengumpulan Data ---
        self.flow_stats = defaultdict(lambda: defaultdict(int))
        self.monitoring_interval = 10
        self.monitor_thread = hub.spawn(self._monitor)
        self.collected_data = []

        # --- Bagian Deteksi ML ---
        self.model = None
        self.scaler = None
        self.feature_columns = [
            'packet_count', 'byte_count', 'duration_sec', 'duration_nsec', 'tx_bytes',
            'rx_bytes', 'byte_per_flow', 'packet_per_flow', 'packet_rate', 'packet_ins',
            'flow_entries', 'tx_kbps', 'rx_kbps', 'port_bandwidth'
        ]
        self._load_model()

    def _load_model(self):
        try:
            self.model = joblib.load('/app/models/best_model.pkl')
            self.scaler = joblib.load('/app/models/scaler.pkl')
            self.model_name = self.model.__class__.__name__
            self.logger.info("✅ Best performing ML model and scaler loaded successfully for real-time detection.")
        except Exception as e:
            self.logger.info(f"⚠️ Could not load ML model: {e}. Controller will run in data collection mode only.")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Switch %d connected', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Switch %d closed', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        """Thread utama yang secara periodik meminta statistik flow."""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.monitoring_interval)

    def _request_stats(self, datapath):
        """Mengirim permintaan statistik flow ke switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Menerima dan memproses balasan statistik flow dari switch (IP dan MAC)."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        # Loop melalui semua flow yang dilaporkan oleh switch
        for stat in body:
            if stat.priority == 0:
                continue
            if 'eth_type' in stat.match and stat.match['eth_type'] == ether_types.ETH_TYPE_ARP:
                continue

            src_id = None
            dst_id = None
            flow_key_part = None

            # Cek apakah ini flow L3 (berbasis IP), ini prioritas kita
            if 'ipv4_src' in stat.match and 'ipv4_dst' in stat.match:
                src_id = stat.match['ipv4_src']
                dst_id = stat.match['ipv4_dst']
                flow_key_part = f"{src_id}-{dst_id}"

            # Jika bukan flow L3, cek apakah ini flow L2 (berbasis MAC)
            elif 'eth_src' in stat.match and 'eth_dst' in stat.match:
                src_id = stat.match['eth_src']
                dst_id = stat.match['eth_dst']
                # Kita tambahkan in_port agar lebih unik untuk flow L2
                in_port = stat.match.get('in_port', '')
                flow_key_part = f"{src_id}-{dst_id}-{in_port}"

            # Jika flow tidak bisa diidentifikasi, lewati
            if not flow_key_part:
                continue

            # Buat flow key yg unik
            flow_key = f"{dpid}-{flow_key_part}"

            # Hitung selisih dari statistik sebelumnya untuk mendapatkan rate
            packet_count_diff = stat.packet_count - self.flow_stats[flow_key]['packet_count']
            byte_count_diff = stat.byte_count - self.flow_stats[flow_key]['byte_count']

            # Update statistik saat ini
            self.flow_stats[flow_key]['packet_count'] = stat.packet_count
            self.flow_stats[flow_key]['byte_count'] = stat.byte_count

            # Hanya proses jika ada lalu lintas baru yang signifikan
            if packet_count_diff > 0:
                self.process_flow_features(dpid, src_id, dst_id, packet_count_diff, byte_count_diff, stat.duration_sec, stat.duration_nsec)

        # Setelah semua statistik dari semua switch diproses, simpan ke file
        if self.collected_data:
            self.save_dataset()

    def process_flow_features(self, dpid, src_ip, dst_ip, packet_count, byte_count, duration_sec, duration_nsec):
        """Menghitung fitur dan menyimpannya."""
        duration = duration_sec + duration_nsec * 1e-9
        duration = max(duration, 1e-9)

        # Hitung fitur
        packet_rate = packet_count / self.monitoring_interval
        tx_kbps = (byte_count * 8) / (self.monitoring_interval * 1000)

        features = {
            'packet_count': packet_count,
            'byte_count': byte_count,
            'switch_id': dpid,
            'duration_sec': duration_sec,
            'duration_nsec': duration_nsec,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port_num': 0,
            'tx_bytes': byte_count,
            'rx_bytes': byte_count,
            'dt': int(time.time()),
            'byte_per_flow': byte_count,
            'packet_per_flow': packet_count,
            'packet_rate': packet_rate,
            'packet_ins': packet_count,
            'flow_entries': 1,
            'tx_kbps': tx_kbps,
            'rx_kbps': tx_kbps,
            'port_bandwidth': 2 * tx_kbps,
        }

        features['label'] = self.classify_traffic(features)

        # Lakukan prediksi real-time jika model ada
        if self.model:
            is_malicious = self.predict_traffic(features)
            if is_malicious == 1:
                self.logger.warning(f"🚨 [{self.model_name}] DDoS Attack Detected from {src_ip}! Rate: {packet_rate:.2f} pps 🚨")

        self.collected_data.append(features)

    def classify_traffic(self, features):
        """Memberi label pada data untuk dataset training (ground truth)."""
        src_id = features['src_ip']
        packet_rate = features['packet_rate']
        if src_id == '10.0.0.100':
            return 0 # Benign (Respons Server)

        # Cek apakah sumbernya adalah botnet yang dikenal (berdasarkan MAC atau IP)
        botnet_macs = [f'00:00:00:00:00:{i:02x}' for i in range(10, 14)]
        botnet_ips = [f'10.0.0.{i}' for i in range(10, 14)]

        if src_id in botnet_macs or src_id in botnet_ips:
            return 1 # Malicious

        # Jika packet rate sangat tinggi dari sumber yang tidak dikenal, anggap malicious
        if packet_rate > 50:
            return 1 # Malicious

        return 0 # Benign

    def predict_traffic(self, features_dict):
        """Memprediksi lalu lintas menggunakan model ML yang sudah dimuat."""
        try:
            features_list = [features_dict.get(col, 0) for col in self.feature_columns]
            df_to_scale = pd.DataFrame([features_list], columns=self.feature_columns)
            scaled_features = self.scaler.transform(df_to_scale)
            prediction = self.model.predict(scaled_features)
            return prediction[0]
        except Exception as e:
            self.logger.error(f"Error during ML prediction: {e}")
            return 0

    def save_dataset(self):
        """Menyimpan data yang terkumpul ke file CSV."""
        if not self.collected_data:
            return

        df = pd.DataFrame(self.collected_data)
        dataset_path = '/app/data/ddos_dataset.csv'
        file_exists = os.path.exists(dataset_path)

        df.to_csv(dataset_path, mode='a', index=False, header=not file_exists)

        self.logger.info(f"Dataset updated with {len(self.collected_data)} new flow entries.")
        self.collected_data = [] # Kosongkan list setelah disimpan


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handler untuk switch yang baru terhubung, install flow default."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac= eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = in_port

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:

            # 'Match' berdasarkan tipe paket (IP atau lainnya)
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                if ip_pkt:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_src=ip_pkt.src,
                                            ipv4_dst=ip_pkt.dst)
                    self.add_flow(datapath, 1, match, actions)
            # Filter data ARP
            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,
                                        in_port=in_port,
                                        eth_src=src_mac,
                                        eth_dst=dst_mac)
                self.add_flow(datapath, 1, match, actions)

            else:
                # Match L2
                match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
                self.add_flow(datapath, 1, match, actions)

        # Kirim paket keluar
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
