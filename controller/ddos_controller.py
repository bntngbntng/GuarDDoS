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

class DDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}  # Untuk menyimpan objek datapath (switch)

        # --- Bagian Monitoring & Pengumpulan Data ---
        self.flow_stats = defaultdict(lambda: defaultdict(int))
        self.monitoring_interval = 15  # Kita percepat interval untuk mendapat lebih banyak data point
        self.monitor_thread = hub.spawn(self._monitor)
        self.collected_data = []

        # --- Bagian Deteksi ML ---
        self.model = None
        self.scaler = None
        # Pastikan nama fitur ini SAMA PERSIS dengan yang digunakan saat training
        self.feature_columns = [
            'packet_count', 'byte_count', 'duration_sec', 'duration_nsec', 'tx_bytes',
            'rx_bytes', 'byte_per_flow', 'packet_per_flow', 'packet_rate', 'packet_ins',
            'flow_entries', 'tx_kbps', 'rx_kbps', 'port_bandwidth'
        ]
        self._load_model()

    def _load_model(self):
        """Mencoba memuat model ML saat startup."""
        try:
            # Selalu muat 'best_model.pkl'
            self.model = joblib.load('/app/models/best_model.pkl')
            self.scaler = joblib.load('/app/models/scaler.pkl')
            self.logger.info("✅ Best performing ML model and scaler loaded successfully for real-time detection.")
        except Exception as e:
            self.logger.info(f"⚠️ Could not load ML model: {e}. Controller will run in data collection mode only.")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Menangani koneksi dan diskoneksi switch."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Switch %d terhubung', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Switch %d terputus', datapath.id)
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
        """Menerima dan memproses balasan statistik flow dari switch."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        for stat in sorted([flow for flow in body if flow.priority == 1], key=lambda flow: (flow.match['in_port'], flow.match['eth_dst'])):
            # Ekstrak info dari flow stat
            in_port = stat.match['in_port']
            eth_src = stat.match['eth_src']
            eth_dst = stat.match['eth_dst']

            # Buat flow key yang unik
            flow_key = f"{dpid}-{eth_src}-{eth_dst}-{in_port}"

            # Hitung selisih dari statistik sebelumnya untuk mendapatkan rate
            packet_count_diff = stat.packet_count - self.flow_stats[flow_key]['packet_count']
            byte_count_diff = stat.byte_count - self.flow_stats[flow_key]['byte_count']

            # Update statistik saat ini
            self.flow_stats[flow_key]['packet_count'] = stat.packet_count
            self.flow_stats[flow_key]['byte_count'] = stat.byte_count

            # Hanya proses jika ada lalu lintas baru
            if packet_count_diff > 0:
                self.process_flow_features(dpid, eth_src, eth_dst, packet_count_diff, byte_count_diff, stat.duration_sec, stat.duration_nsec)

        # Setelah semua statistik dari semua switch diproses, simpan ke file
        if self.collected_data:
            self.save_dataset()

    def process_flow_features(self, dpid, src_ip, dst_ip, packet_count, byte_count, duration_sec, duration_nsec):
        """Menghitung fitur dan menyimpannya."""
        # Duration tidak bisa 0 untuk menghindari ZeroDivisionError
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
            'src_ip': src_ip, # Note: ini adalah MAC address, tapi kita anggap IP untuk konsistensi
            'dst_ip': dst_ip,
            'port_num': 0, # Port tidak tersedia di flow stat level ini, kita set 0
            'tx_bytes': byte_count,
            'rx_bytes': byte_count,
            'dt': int(hub.time.time()),
            'byte_per_flow': byte_count,
            'packet_per_flow': packet_count,
            'packet_rate': packet_rate,
            'packet_ins': packet_count,
            'flow_entries': 1,
            'tx_kbps': tx_kbps,
            'rx_kbps': tx_kbps,
            'port_bandwidth': 2 * tx_kbps,
        }

        # Beri label untuk dataset training
        features['label'] = self.classify_traffic(features)

        # Lakukan prediksi real-time jika model ada
        if self.model:
            is_malicious = self.predict_traffic(features)
            if is_malicious == 1:
                self.logger.warning(f"🚨 DDoS Attack Detected from {src_ip} via Switch {dpid}! Rate: {packet_rate:.2f} pps 🚨")

        self.collected_data.append(features)

    def classify_traffic(self, features):
        """Memberi label pada data untuk dataset training (ground truth)."""
        src_ip = features['src_ip']
        packet_rate = features['packet_rate']
        botnet_macs = [f'00:00:00:00:00:{i:02x}' for i in range(10, 14)] # MAC untuk bot10-bot13

        if src_ip in botnet_macs:
            return 1 # Malicious
        if packet_rate > 50: # Turunkan threshold karena interval lebih cepat
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
        """Handler untuk PacketIn, hanya untuk switching, bukan data collection."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return # abaikan lldp

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Belajar MAC address untuk port forwarding
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            # Kita tetap install flow agar switch tidak terus-terusan kirim PacketIn
            # Kita bisa set timeout agar flow bisa di-refresh
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
