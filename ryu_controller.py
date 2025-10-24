"""
SDN-DDoS Dataset Generation - Ryu Controller
This controller collects flow statistics and generates labeled CSV datasets
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.lib import hub
import csv
import time
from datetime import datetime
import os

class SDNDDoSCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNDDoSCollector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        # Flow tracking
        self.flow_stats = {}
        self.flow_history = {}
        
        # CSV output
        self.csv_filename = f'sdn_ddos_dataset_{int(time.time())}.csv'
        self.init_csv()
        
        # Start periodic flow stats collection
        self.monitor_thread = hub.spawn(self._monitor)
        
        # Attack tracking (for labeling)
        self.attacker_ips = set()  # IPs performing attacks
        self.attack_start_time = None
        
    def init_csv(self):
        """Initialize CSV file with headers"""
        headers = [
            'timestamp', 'datapath_id', 'flow_id', 
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
            'duration_sec', 'duration_nsec', 'idle_timeout', 'hard_timeout',
            'priority', 'packet_count', 'byte_count',
            'packet_rate', 'byte_rate', 'flow_speed',
            'packets_per_flow', 'bytes_per_packet', 'bytes_per_flow',
            'flow_duration', 'flow_iat', 'active_time',
            'label'
        ]
        
        with open(self.csv_filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
        
        self.logger.info(f"CSV file initialized: {self.csv_filename}")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.datapaths[datapath.id] = datapath
        self.logger.info(f"Switch connected: {datapath.id}")
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, 
                 idle_timeout=0, hard_timeout=0):
        """Add a flow entry to switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle packet-in events"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})
        
        # Learn MAC address
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, 
                             idle_timeout=10, hard_timeout=30)
                return
            else:
                self.add_flow(datapath, 1, match, actions,
                             idle_timeout=10, hard_timeout=30)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _monitor(self):
        """Periodic flow statistics collection"""
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)  # Collect stats every 5 seconds

    def _request_stats(self, datapath):
        """Request flow statistics from switch"""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply"""
        body = ev.msg.body
        datapath = ev.msg.datapath
        
        current_time = time.time()
        
        for stat in body:
            # Skip table-miss entry
            if stat.priority == 0:
                continue
            
            # Extract flow features
            flow_id = self._generate_flow_id(stat, datapath.id)
            
            # Get previous stats for rate calculation
            prev_stat = self.flow_history.get(flow_id, None)
            
            # Extract match fields
            src_ip = stat.match.get('ipv4_src', '0.0.0.0')
            dst_ip = stat.match.get('ipv4_dst', '0.0.0.0')
            src_port = stat.match.get('tcp_src', stat.match.get('udp_src', 0))
            dst_port = stat.match.get('tcp_dst', stat.match.get('udp_dst', 0))
            protocol = stat.match.get('ip_proto', 0)
            
            # Calculate derived metrics
            duration = stat.duration_sec + stat.duration_nsec / 1e9
            
            if prev_stat and duration > 0:
                time_diff = current_time - prev_stat['timestamp']
                packet_rate = (stat.packet_count - prev_stat['packet_count']) / time_diff if time_diff > 0 else 0
                byte_rate = (stat.byte_count - prev_stat['byte_count']) / time_diff if time_diff > 0 else 0
                flow_speed = packet_rate
                flow_iat = time_diff
            else:
                packet_rate = stat.packet_count / duration if duration > 0 else 0
                byte_rate = stat.byte_count / duration if duration > 0 else 0
                flow_speed = packet_rate
                flow_iat = 0
            
            bytes_per_packet = stat.byte_count / stat.packet_count if stat.packet_count > 0 else 0
            
            # Apply heuristic labeling
            label = self._label_flow(src_ip, dst_ip, packet_rate, byte_rate, 
                                    stat.packet_count, bytes_per_packet)
            
            # Prepare row data
            row = [
                datetime.now().isoformat(),
                datapath.id,
                flow_id,
                src_ip, dst_ip, src_port, dst_port, protocol,
                stat.duration_sec, stat.duration_nsec,
                stat.idle_timeout, stat.hard_timeout, stat.priority,
                stat.packet_count, stat.byte_count,
                packet_rate, byte_rate, flow_speed,
                stat.packet_count, bytes_per_packet, stat.byte_count,
                duration, flow_iat, duration,
                label
            ]
            
            # Write to CSV
            with open(self.csv_filename, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(row)
            
            # Store current stats for next iteration
            self.flow_history[flow_id] = {
                'timestamp': current_time,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count
            }

    def _generate_flow_id(self, stat, dpid):
        """Generate unique flow identifier"""
        match = stat.match
        src_ip = match.get('ipv4_src', '0.0.0.0')
        dst_ip = match.get('ipv4_dst', '0.0.0.0')
        src_port = match.get('tcp_src', match.get('udp_src', 0))
        dst_port = match.get('tcp_dst', match.get('udp_dst', 0))
        protocol = match.get('ip_proto', 0)
        
        return f"{dpid}_{src_ip}_{dst_ip}_{src_port}_{dst_port}_{protocol}"

    def _label_flow(self, src_ip, dst_ip, packet_rate, byte_rate, 
                    packet_count, bytes_per_packet):
        """
        Heuristic-based flow labeling
        DDoS characteristics:
        - High packet rate (>1000 pps)
        - High flow count from single source
        - Small packet sizes (<100 bytes for some attacks)
        - Short duration, high volume
        """
        # Check if source is known attacker
        if src_ip in self.attacker_ips:
            return 1
        
        # Heuristic rules for DDoS detection
        if packet_rate > 1000:  # Very high packet rate
            return 1
        
        if packet_rate > 500 and bytes_per_packet < 100:  # High rate + small packets
            return 1
        
        if packet_rate > 300 and packet_count > 5000:  # Sustained high rate
            return 1
        
        # Default to normal
        return 0
    
    def mark_attacker(self, ip_address):
        """Manually mark an IP as attacker for labeling"""
        self.attacker_ips.add(ip_address)
        self.logger.info(f"Marked {ip_address} as attacker")
