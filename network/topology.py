#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import threading

class DDoSTopology:
    def __init__(self):
        self.net = None
        self.hosts = []
        self.switches = []
        
    def create_topology(self):
        """Create network topology for DDoS simulation"""
        info("*** Creating network topology\n")
        
        # Create Mininet instance with remote controller
        self.net = Mininet(
            controller=RemoteController,
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True
        )
        
        # Add controller
        controller = self.net.addController(
            'c0',
            controller=RemoteController,
            ip='127.0.0.1',
            port=6633
        )
        
        # Add switches
        s1 = self.net.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.net.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.net.addSwitch('s3', protocols='OpenFlow13')
        self.switches = [s1, s2, s3]
        
        # Add hosts (simulate IoT devices)
        # Legitimate hosts
        h1 = self.net.addHost('h1', ip='10.0.0.1/24')
        h2 = self.net.addHost('h2', ip='10.0.0.2/24')
        h3 = self.net.addHost('h3', ip='10.0.0.3/24')
        
        # Target server
        server = self.net.addHost('server', ip='10.0.0.100/24')
        
        # Botnet hosts (attackers)
        bot1 = self.net.addHost('bot1', ip='10.0.0.10/24')
        bot2 = self.net.addHost('bot2', ip='10.0.0.11/24')
        bot3 = self.net.addHost('bot3', ip='10.0.0.12/24')
        bot4 = self.net.addHost('bot4', ip='10.0.0.13/24')
        
        self.hosts = [h1, h2, h3, server, bot1, bot2, bot3, bot4]
        
        # Add links
        # Connect hosts to switches
        self.net.addLink(h1, s1, bw=10)
        self.net.addLink(h2, s1, bw=10)
        self.net.addLink(bot1, s1, bw=10)
        self.net.addLink(bot2, s1, bw=10)
        
        self.net.addLink(h3, s2, bw=10)
        self.net.addLink(bot3, s2, bw=10)
        self.net.addLink(bot4, s2, bw=10)
        
        self.net.addLink(server, s3, bw=100)
        
        # Connect switches
        self.net.addLink(s1, s3, bw=50)
        self.net.addLink(s2, s3, bw=50)
        
        return self.net
    
    def start_network(self):
        """Start the network"""
        info("*** Starting network\n")
        self.net.start()
        
        # Wait for network to stabilize
        time.sleep(5)
        
        info("*** Network started successfully\n")
        return True
    
    def cleanup(self):
        """Clean up network"""
        if self.net:
            self.net.stop()
