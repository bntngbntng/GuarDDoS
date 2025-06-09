#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, icmp
import time
import json
import threading
from collections import defaultdict
import pandas as pd
import os
import joblib

class DDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Flow monitoring data
        self.flow_stats = {}
        self.switch_stats = defaultdict(dict)
        self.port_stats = defaultdict(dict)
        
        # Monitoring interval (30 seconds as per dataset specification)
        self.monitoring_interval = 30
        
        # Data collection
        self.collected_data = []
        self.data_lock = threading.Lock()
        self.monitoring_active = True
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_flows)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Flow table for packet counting
        self.packet_count = defaultdict(int)
        self.byte_count = defaultdict(int)
        super(DDoSController, self).__init__(*args, **kwargs)

        self.model = None
        self.scaler = None
        self.feature_columns = [
            'packet_count', 'byte_count', 'duration_sec', 'duration_nsec',
            'tx_bytes', 'rx_bytes', 'byte_per_flow', 'packet_per_flow',
            'packet_rate', 'packet_ins', 'flow_entries', 'tx_kbps', 'rx_kbps',
            'port_bandwidth'
        ]

        try:
            self.model = joblib.load('/app/models/random_forest_model.pkl')
            self.scaler = joblib.load('/app/models/scaler.pkl')
            self.logger.info("ML model and scaler loaded successfully for real-time detection.")
        except Exception as e:
            self.logger.error(f"Could not load ML model: {e}. Controller will run without ML-based detection.")
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install default flow - send unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info("Switch %s connected", datapath.id)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """Add flow entry to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                           actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match,
                                  instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packet-in events"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Skip LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Extract packet information for monitoring
        self.extract_packet_info(pkt, dpid, in_port)
        
        # Simple learning switch behavior
        self.mac_to_port.setdefault(dpid, {})
        
        # Learn source MAC
        self.mac_to_port[dpid][src] = in_port
        
        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        # Create match and actions
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow if not flooding
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            return
        
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def extract_packet_info(self, pkt, switch_id, in_port):
        """Extract packet information for dataset"""
        timestamp = time.time()
        
        # Get IP packet
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return
        
        # Extract basic info
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        protocol = ip_pkt.proto
        
        # Get transport layer info
        port_num = 0
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        if tcp_pkt:
            port_num = tcp_pkt.dst_port
        elif udp_pkt:
            port_num = udp_pkt.dst_port
        
        # Create flow key
        flow_key = f"{src_ip}-{dst_ip}-{protocol}-{port_num}"
        
        # Update counters
        self.packet_count[flow_key] += 1
        self.byte_count[flow_key] += len(pkt.data)
        
        # Store packet info for monitoring
        packet_info = {
            'timestamp': timestamp,
            'switch_id': switch_id,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'port_num': port_num,
            'protocol': protocol,
            'flow_key': flow_key,
            'packet_size': len(pkt.data)
        }
        
        with self.data_lock:
            if not hasattr(self, 'current_packets'):
                self.current_packets = []
            self.current_packets.append(packet_info)
    
    def monitor_flows(self):
        """Monitor flows and collect statistics"""
        while self.monitoring_active:
            time.sleep(self.monitoring_interval)
            self.collect_flow_stats()
    
    def collect_flow_stats(self):
        """Collect and process flow statistics"""
        timestamp = time.time()
        
        with self.data_lock:
            if not hasattr(self, 'current_packets'):
                return
            
            # Process collected packets
            flow_stats = defaultdict(lambda: {
                'packet_count': 0,
                'byte_count': 0,
                'src_ip': '',
                'dst_ip': '', 
                'port_num': 0,
                'switch_id': 0,
                'duration': 0,
                'first_seen': timestamp,
                'last_seen': timestamp
            })
            
            for pkt_info in self.current_packets:
                flow_key = pkt_info['flow_key']
                stats = flow_stats[flow_key]
                
                stats['packet_count'] += 1
                stats['byte_count'] += pkt_info['packet_size']
                stats['src_ip'] = pkt_info['src_ip']
                stats['dst_ip'] = pkt_info['dst_ip']
                stats['port_num'] = pkt_info['port_num']
                stats['switch_id'] = pkt_info['switch_id']
                stats['last_seen'] = pkt_info['timestamp']
                
                if stats['packet_count'] == 1:
                    stats['first_seen'] = pkt_info['timestamp']
            
            # Calculate features and save data
            for flow_key, stats in flow_stats.items():
                self.calculate_and_save_features(flow_key, stats, timestamp)
            

            if flow_stats:
                self.save_dataset()

            # Clear current packets
            self.current_packets = []
    
    def calculate_and_save_features(self, flow_key, stats, timestamp):
        """Calculate features and save to dataset"""
        duration = max(stats['last_seen'] - stats['first_seen'], 0.001)
        
        # Calculate features as per dataset specification
        features = {
            'packet_count': stats['packet_count'],
            'byte_count': stats['byte_count'],
            'switch_id': stats['switch_id'],
            'duration_sec': int(duration),
            'duration_nsec': int((duration % 1) * 1e9),
            'src_ip': stats['src_ip'],
            'dst_ip': stats['dst_ip'],
            'port_num': stats['port_num'],
            'tx_bytes': stats['byte_count'],
            'rx_bytes': stats['byte_count'],
            'dt': int(timestamp),
            'byte_per_flow': stats['byte_count'],
            'packet_per_flow': stats['packet_count'],
            'packet_rate': stats['packet_count'] / self.monitoring_interval,
            'packet_ins': stats['packet_count'],
            'flow_entries': 1,
            'tx_kbps': (stats['byte_count'] * 8) / (self.monitoring_interval * 1000),
            'rx_kbps': (stats['byte_count'] * 8) / (self.monitoring_interval * 1000),
            'port_bandwidth': 2 * (stats['byte_count'] * 8) / (self.monitoring_interval * 1000),
        }
        features['label'] = self.classify_traffic(flow_key, stats)
        is_malicious = self.predict_traffic(features)
        if is_malicious == 1:
            self.logger.warning(f"DDoS Attack Detected from {stats['src_ip']} to {stats['dst_ip']}!")
        # Save to collected data
        self.collected_data.append(features)

    def classify_traffic(self, flow_key, stats):
        """Classify traffic as benign (0) or malicious (1) for dataset LABELING."""
        # Simple classification based on source IP and packet rate for creating ground truth
        src_ip = stats['src_ip']
        packet_rate = stats['packet_count'] / self.monitoring_interval

        # Mark botnet IPs as malicious for the training data
        botnet_ips = ['10.0.0.10', '10.0.0.11', '10.0.0.12', '10.0.0.13']

        if src_ip in botnet_ips:
            return 1  # Malicious

        # High packet rate might also indicate an attack
        if packet_rate > 100:  # Threshold for DDoS detection
            return 1  # Malicious

        return 0  # Benign

    def predict_traffic(self, features_dict):

        if not self.model or not self.scaler:
            if features_dict['packet_rate'] > 100:
                return 1 # Malicious
            else:
                return 0 # Benign
        try:
            features_list = [features_dict[col] for col in self.feature_columns]
            # Buat DataFrame dengan satu baris untuk scaling
            df_to_scale = pd.DataFrame([features_list], columns=self.feature_columns)

            # Scale features
            scaled_features = self.scaler.transform(df_to_scale)

            # Prediksi
            prediction = self.model.predict(scaled_features)
            return prediction[0]
        except Exception as e:
            self.logger.error(f"Error during prediction: {e}")
            return 0
    
    def save_dataset(self):
        """Save collected data to CSV file"""
        if not self.collected_data:
            return

        df = pd.DataFrame(self.collected_data)
        dataset_path = '/app/data/ddos_dataset.csv'
        file_exists = os.path.exists(dataset_path)
        df.to_csv(dataset_path, mode='a', index=False, header=not file_exists)

        self.logger.info(f"Dataset updated with {len(self.collected_data)} new samples.")
        self.collected_data = []

    def get_statistics(self):
        """Get current statistics"""
        return {
            'total_samples': len(self.collected_data),
            'malicious_samples': sum(1 for d in self.collected_data if d['label'] == 1),
            'benign_samples': sum(1 for d in self.collected_data if d['label'] == 0)
        }

    # Initialize MAC table
    mac_to_port = {}
