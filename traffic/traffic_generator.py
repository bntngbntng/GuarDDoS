#!/usr/bin/env python3

import threading
import time
import subprocess
import random
from scapy.all import *

class TrafficGenerator:
    def __init__(self, net):
        self.net = net
        self.is_running = False
        
    def start_benign_traffic(self):
        """Generate benign network traffic"""
        def generate_benign():
            hosts = ['h1', 'h2', 'h3']
            server = 'server'
            
            while self.is_running:
                # HTTP-like traffic
                for host in hosts:
                    if random.random() < 0.3:  # 30% chance
                        self.net.get(host).cmd(f'ping -c 1 10.0.0.100 &')
                        
                    if random.random() < 0.2:  # 20% chance  
                        self.net.get(host).cmd(f'wget -q -O /dev/null http://10.0.0.100:8000/ &')
                
                time.sleep(random.uniform(1, 5))
        
        thread = threading.Thread(target=generate_benign)
        thread.daemon = True
        thread.start()
    
    def start_ddos_attack(self, attack_type='syn_flood', duration=60):
        """Start DDoS attack simulation"""
        def launch_attack():
            botnets = ['bot1', 'bot2', 'bot3', 'bot4']
            target_ip = '10.0.0.100'
            
            print(f"Starting {attack_type} attack for {duration} seconds...")
            
            if attack_type == 'syn_flood':
                self.syn_flood_attack(botnets, target_ip, duration)
            elif attack_type == 'udp_flood':
                self.udp_flood_attack(botnets, target_ip, duration)
            elif attack_type == 'icmp_flood':
                self.icmp_flood_attack(botnets, target_ip, duration)
            
        thread = threading.Thread(target=launch_attack)
        thread.daemon = True
        thread.start()
    
    def syn_flood_attack(self, botnets, target_ip, duration):
        """TCP SYN Flood Attack"""
        for bot in botnets:
            def bot_attack():
                    # High-rate SYN flood
                    cmd = f'hping3 -S -p 80 --flood {target_ip}'
                    print(f"Bot {bot} starting SYN flood...")
                    self.net.get(bot).cmd(f'{cmd} &')

            thread = threading.Thread(target=bot_attack)
            thread.daemon = True
            thread.start()
    
    def udp_flood_attack(self, botnets, target_ip, duration):
        """UDP Flood Attack"""
        for bot in botnets:
            def bot_attack():
                    # UDP flood with random ports
                    port = random.randint(1000, 9000)
                    cmd = f'hping3 -2 -p {port} --flood {target_ip}'
                    print(f"Bot {bot} starting UDP flood...")
                    self.net.get(bot).cmd(f'{cmd} &')
            
            thread = threading.Thread(target=bot_attack)
            thread.daemon = True
            thread.start()
    
    def icmp_flood_attack(self, botnets, target_ip, duration):
        """ICMP Flood Attack"""
        for bot in botnets:
            def bot_attack():
                    # ICMP flood
                    cmd = f'ping -f {target_ip}'
                    print(f"Bot {bot} starting ICMP flood...")
                    self.net.get(bot).cmd(f'{cmd} &')
            
            thread = threading.Thread(target=bot_attack)
            thread.daemon = True
            thread.start()
    
    def start_traffic_generation(self, duration=300):
        """Start mixed traffic generation"""
        self.is_running = True
        
        # Start benign traffic
        self.start_benign_traffic()
        
        # Schedule different types of attacks
        attacks = [
            {'type': 'syn_flood', 'start': 60, 'duration': 90},
            {'type': 'udp_flood', 'start': 180, 'duration': 60},
            {'type': 'icmp_flood', 'start': 270, 'duration': 30}
        ]
        
        def schedule_attacks():
            start_time = time.time()
            for attack in attacks:
                # Wait for attack start time
                while time.time() - start_time < attack['start']:
                    time.sleep(1)
                
                if self.is_running:
                    self.start_ddos_attack(attack['type'], attack['duration'])
        
        attack_thread = threading.Thread(target=schedule_attacks)
        attack_thread.daemon = True
        attack_thread.start()
        
        
        print("Traffic generation threads started in the background.")
