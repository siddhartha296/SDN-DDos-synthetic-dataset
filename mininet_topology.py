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

def run_topology(topology_class, duration=300, controller_ip='127.0.0.1', 
                controller_port=6653, topo_name="custom"):
    """
    Run a specific topology and generate traffic
    
    Args:
        topology_class: Topology class to instantiate
        duration: Duration to run the topology (seconds)
        controller_ip: Ryu controller IP
        controller_port: Ryu controller port
        topo_name: Name for logging
    """
    print(f"\n{'='*60}")
    print(f"Starting topology: {topo_name}")
    print(f"{'='*60}\n")
    
    # Create topology
    topo = topology_class(num_switches=4, hosts_per_switch=3,
                          bandwidth=100, delay='5ms', loss=0)
    
    # Create network
    net = Mininet(topo=topo,
                  controller=lambda name: RemoteController(
                      name, ip=controller_ip, port=controller_port),
                  link=TCLink,
                  autoSetMacs=True,
                  autoStaticArp=True)
    
    net.start()
    
    print("Network started. Generating traffic...")
    
    # Get all hosts
    hosts = net.hosts
    
    # Designate some hosts as attackers (20% of hosts)
    num_attackers = max(1, len(hosts) // 5)
    attackers = random.sample(hosts, num_attackers)
    normal_hosts = [h for h in hosts if h not in attackers]
    
    print(f"Normal hosts: {len(normal_hosts)}")
    print(f"Attacker hosts: {len(attackers)}")
    
    # Generate normal traffic
    generate_normal_traffic(normal_hosts, duration)
    
    # Generate attack traffic (start after some normal traffic)
    time.sleep(duration * 0.3)  # Wait 30% of duration
    generate_attack_traffic(attackers, normal_hosts, duration * 0.7)
    
    print(f"\nTraffic generation complete. Keeping network alive...")
    time.sleep(10)  # Keep network alive for final stats collection
    
    # Cleanup
    net.stop()
    print(f"Topology {topo_name} completed.\n")

def generate_normal_traffic(hosts, duration):
    """Generate normal traffic patterns"""
    print("Generating normal traffic...")
    
    for host in hosts:
        # HTTP-like traffic
        target = random.choice([h for h in hosts if h != host])
        host.cmd(f'timeout {duration} ping -i 0.5 {target.IP()} > /dev/null 2>&1 &')
        
        # Occasional larger transfers
        if random.random() < 0.3:
            target = random.choice([h for h in hosts if h != host])
            host.cmd(f'timeout {duration/2} iperf -c {target.IP()} -t {duration/2} -b 10M > /dev/null 2>&1 &')

def generate_attack_traffic(attackers, targets, duration):
    """Generate DDoS attack traffic"""
    print("Generating DDoS attack traffic...")
    
    # Select victim(s)
    victims = random.sample(targets, min(2, len(targets)))
    
    for attacker in attackers:
        for victim in victims:
            # High-rate ICMP flood
            attacker.cmd(f'timeout {duration} hping3 --icmp --flood {victim.IP()} > /dev/null 2>&1 &')
            
            # SYN flood
            attacker.cmd(f'timeout {duration} hping3 -S --flood -p 80 {victim.IP()} > /dev/null 2>&1 &')
            
            # UDP flood
            attacker.cmd(f'timeout {duration} hping3 --udp --flood -p 53 {victim.IP()} > /dev/null 2>&1 &')

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
    duration_per_topology = 300  # 5 minutes per topology
    
    print("\n" + "="*60)
    print("SDN-DDoS Dataset Generation Pipeline")
    print("="*60)
    print(f"Controller: {controller_ip}:{controller_port}")
    print(f"Duration per topology: {duration_per_topology} seconds")
    print(f"Total topologies: {len(topologies)}")
    print("="*60 + "\n")
    
    for i, (topo_class, topo_name) in enumerate(topologies, 1):
        print(f"\n[{i}/{len(topologies)}] Running {topo_name} topology...")
        run_topology(topo_class, duration_per_topology, 
                    controller_ip, controller_port, topo_name)
        
        # Wait between topologies
        if i < len(topologies):
            print(f"Waiting 30 seconds before next topology...\n")
            time.sleep(30)
    
    print("\n" + "="*60)
    print("All topologies completed!")
    print("Dataset files have been generated in the current directory")
    print("="*60 + "\n")

if __name__ == '__main__':
    main()

