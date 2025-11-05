"""
Mininet Topology Generator for SDN-DDoS Dataset
Creates various network topologies for diverse traffic patterns
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import random
import time
import os
import json
import requests # This must be installed (sudo pip3 install requests)


class CustomTopology(Topo):
    """Base class for custom topologies"""
    
    def __init__(self, num_switches=4, hosts_per_switch=3, 
                 bandwidth=100, delay='5ms', loss=0):
        
        # Set attributes *before* calling super().__init__
        # The Mininet Topo class calls build() within its __init__,
        # so these attributes must exist first.
        self.num_switches = num_switches
        self.hosts_per_switch = hosts_per_switch
        self.bandwidth = bandwidth
        self.delay = delay
        self.loss = loss

        super(CustomTopology, self).__init__()

class LinearTopology(CustomTopology):
    """Linear topology: S1-S2-S3-S4"""
    
    def build(self):
        switches = []
        
        # Create switches
        for i in range(1, self.num_switches + 1):
            switch = self.addSwitch(f's{i}')
            switches.append(switch)
        
        # Connect switches in a line
        for i in range(len(switches) - 1):
            self.addLink(switches[i], switches[i+1],
                        cls=TCLink,
                        bw=self.bandwidth,
                        delay=self.delay,
                        loss=self.loss)
        
        # Add hosts to each switch
        for i, switch in enumerate(switches, 1):
            for j in range(1, self.hosts_per_switch + 1):
                host = self.addHost(f'h{i}{j}')
                self.addLink(host, switch,
                           cls=TCLink,
                           bw=self.bandwidth/2,
                           delay='2ms')

class TreeTopology(CustomTopology):
    """Tree topology: hierarchical structure"""
    
    def build(self):
        # Core switch
        core = self.addSwitch('s1')
        
        # Aggregation switches
        agg_switches = []
        for i in range(2, self.num_switches + 1):
            agg = self.addSwitch(f's{i}')
            agg_switches.append(agg)
            self.addLink(core, agg,
                        cls=TCLink,
                        bw=self.bandwidth,
                        delay=self.delay,
                        loss=self.loss)
        
        # Add hosts to aggregation switches
        host_id = 1
        for agg in agg_switches:
            for j in range(self.hosts_per_switch):
                host = self.addHost(f'h{host_id}')
                self.addLink(host, agg,
                           cls=TCLink,
                           bw=self.bandwidth/2,
                           delay='2ms')
                host_id += 1

class MeshTopology(CustomTopology):
    """Mesh topology: switches connected to multiple switches"""
    
    def build(self):
        switches = []
        
        # Create switches
        for i in range(1, self.num_switches + 1):
            switch = self.addSwitch(f's{i}')
            switches.append(switch)
        
        # Create mesh connections
        for i in range(len(switches)):
            for j in range(i+1, len(switches)):
                # Connect each switch to 2-3 other switches
                if random.random() < 0.6:
                    self.addLink(switches[i], switches[j],
                               cls=TCLink,
                               bw=self.bandwidth,
                               delay=self.delay,
                               loss=self.loss)
        
        # Add hosts
        host_id = 1
        for switch in switches:
            for j in range(self.hosts_per_switch):
                host = self.addHost(f'h{host_id}')
                self.addLink(host, switch,
                           cls=TCLink,
                           bw=self.bandwidth/2,
                           delay='2ms')
                host_id += 1

class DataCenterTopology(CustomTopology):
    """Data center like topology with core, aggregation, and edge layers"""
    
    def build(self):
        # Core switches
        core1 = self.addSwitch('s1')
        core2 = self.addSwitch('s2')
        self.addLink(core1, core2, cls=TCLink, bw=self.bandwidth*2)
        
        # Aggregation layer
        agg_switches = []
        for i in range(3, 7):
            agg = self.addSwitch(f's{i}')
            agg_switches.append(agg)
            # Connect to both core switches
            self.addLink(agg, core1, cls=TCLink, bw=self.bandwidth)
            self.addLink(agg, core2, cls=TCLink, bw=self.bandwidth)
        
        # Edge switches and hosts
        edge_id = 7
        host_id = 1
        for agg in agg_switches:
            for e in range(2):
                edge = self.addSwitch(f's{edge_id}')
                self.addLink(edge, agg, cls=TCLink, bw=self.bandwidth/2)
                
                # Add hosts to edge switch
                for h in range(self.hosts_per_switch):
                    host = self.addHost(f'h{host_id}')
                    self.addLink(host, edge, cls=TCLink, bw=10, delay='1ms')
                    host_id += 1
                
                edge_id += 1

def notify_controller(controller_ip, controller_rest_port, attacker_hosts, clear=False):
    """
    Notify the Ryu controller about attacker IPs via REST API
    """
    
    url = f"http://{controller_ip}:{controller_rest_port}/ddos/clear"
    action_msg = "Clearing attacker list"
    payload = None
    
    if not clear:
        url = f"http://{controller_ip}:{controller_rest_port}/ddos/attackers"
        attacker_ips = [h.IP() for h in attacker_hosts]
        payload = {'ips': attacker_ips}
        action_msg = f"Notifying controller of {len(attacker_ips)} attackers"
    
    print(f"\n{action_msg} at {url}...")
    
    try:
        if payload:
            response = requests.post(url, json=payload, timeout=5)
        else:
            response = requests.post(url, timeout=5)
        
        if response.status_code == 200:
            print(f"  SUCCESS: Controller acknowledged request. Response: {response.text}")
        else:
            print(f"  ERROR: Controller returned status code {response.status_code}")
            print(f"  Response: {response.text}")
            
    except requests.exceptions.ConnectionError as e:
        print("\n" + "="*50)
        print("  CRITICAL ERROR: CONNECTION FAILED.")
        print(f"  URL: {url}")
        print("  1. Is the Ryu controller (ryu_controller.py) running?")
        print("  2. Is it listening on port 8080?")
        print("="*50 + "\n")
    except Exception as e:
        print(f"  An unexpected error occurred: {e}")


def run_topology(topology_class, duration=300, controller_ip='127.0.0.1', 
                controller_port=6653, topo_name="custom"):
    """
    Run a specific topology and generate traffic
    """
    controller_rest_port = 8080
    
    # <<< MODIFIED: Check for hping3
    # Note: This checks a common path. If hping3 is elsewhere, this might fail.
    # The 'which hping3' command in the shell is the best check.
    hping3_path = '/usr/sbin/hping3'
    if not os.path.exists(hping3_path):
        print("="*60)
        print(f"CRITICAL ERROR: 'hping3' not found at {hping3_path}")
        print("This script CANNOT generate attack traffic without it.")
        print("Please install it: sudo apt-get install hping3")
        print("="*60)
        return # Stop this topology run
    # >>> END MODIFIED
    
    print(f"\n{'='*60}")
    print(f"Starting topology: {topo_name}")
    print(f"{'='*60}\n")
    
    topo = topology_class(num_switches=4, hosts_per_switch=3,
                          bandwidth=100, delay='5ms', loss=0)
    
    net = Mininet(topo=topo,
                  controller=lambda name: RemoteController(
                      name, ip=controller_ip, port=controller_port),
                  link=TCLink,
                  autoSetMacs=True,
                  autoStaticArp=True)
    
    try:
        net.start()
        
        print("Network started. Waiting 5s for switches to connect...")
        time.sleep(5) 
        
        print("Generating traffic...")
        
        hosts = net.hosts
        
        num_attackers = max(1, int(len(hosts) * 0.4)) 
        attackers = random.sample(hosts, num_attackers)
        normal_hosts = [h for h in hosts if h not in attackers]
        
        print(f"Normal hosts: {len(normal_hosts)}")
        print(f"Attacker hosts: {len(attackers)} ({[h.IP() for h in attackers]})")
        
        generate_normal_traffic(normal_hosts, duration)
        
        # Wait for normal traffic to establish
        time.sleep(duration * 0.3)
        
        print("\nSTARTING ATTACK")
        notify_controller(controller_ip, controller_rest_port, attackers, clear=False)
        
        attack_duration = duration * 0.7
        generate_attack_traffic(attackers, normal_hosts, attack_duration)
        
        # We must wait for the attack to actually run
        print(f"\nAttack is running for {attack_duration} seconds...")
        time.sleep(attack_duration)
        
        print(f"\nTraffic generation complete. Keeping network alive...")
        time.sleep(10) # Cooldown period
    
    finally:
        print("\nSTOPPING ATTACK")
        notify_controller(controller_ip, controller_rest_port, [], clear=True)
        time.sleep(2)
        
        net.stop()
        print(f"Topology {topo_name} completed.\n")

def generate_normal_traffic(hosts, duration):
    """Generate normal traffic patterns"""
    print("Generating normal traffic...")
    
    if not hosts:
        print("No normal hosts to generate traffic.")
        return

    for host in hosts:
        target = random.choice([h for h in hosts if h != host])
        host.cmd(f'timeout {duration} ping -i 0.3 {target.IP()} > /dev/null 2>&1 &')
        
        if random.random() < 0.4:
            target = random.choice([h for h in hosts if h != host])
            host.cmd(f'timeout {duration/2} iperf -c {target.IP()} -t {duration/2} -b 20M > /dev/null 2>&1 &')

def generate_attack_traffic(attackers, targets, duration):
    """Generate DDoS attack traffic"""
    print("Generating DDoS attack traffic...")
    
    if not targets or not attackers:
        print("No attackers or targets for attack.")
        return
        
    for attacker in attackers:
        for victim in targets:
            # <<< MODIFIED: Removed /dev/null to see errors
            attacker.cmd(f'timeout {duration} hping3 --icmp --flood {victim.IP()} &')
            attacker.cmd(f'timeout {duration} hping3 -S --flood -p 80 {victim.IP()} &')
            attacker.cmd(f'timeout {duration} hping3 --udp --flood -p 53 {victim.IP()} &')
            # >>> END MODIFIED

def main():
    """Main function to run all topologies"""
    setLogLevel('info')
    
    topologies = [
        (LinearTopology, "Linear"),
        (TreeTopology, "Tree"),
        (MeshTopology, "Mesh"),
        (DataCenterTopology, "DataCenter"),
    ]
    
    controller_ip = '127.0.0.1'
    controller_port = 6653
    duration_per_topology = 300
    
    print("\n" + "="*60)
    print("SDN-DDoS Dataset Generation Pipeline")
    print("="*60)
    print(f"Controller: {controller_ip}:{controller_port}")
    print(f"Controller REST API: {controller_ip}:8080") 
    print(f"Duration per topology: {duration_per_topology} seconds")
    print(f"Total topologies: {len(topologies)}")
    print("="*60 + "\n")
    
    for i, (topo_class, topo_name) in enumerate(topologies, 1):
        print(f"\n[{i}/{len(topologies)}] Running {topo_name} topology...")
        run_topology(topo_class, duration_per_topology, 
                    controller_ip, controller_port, topo_name)
        
        if i < len(topologies):
            print(f"Waiting 30 seconds before next topology...\n")
            time.sleep(30)
    
    print("\n" + "="*60)
    print("All topologies completed!")
    print("Dataset files have been generated in the current directory")
    print("="*60 + "\n")

if __name__ == '__main__':
    main()