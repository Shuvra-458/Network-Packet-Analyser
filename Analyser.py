import scapy.all as scapy
import time
import csv
from collections import defaultdict

# Rule 1: Common destination ports for TCP and UDP
def check_common_ports(pkt, device_ip):
   common_ports = [80, 443, 53]
   if pkt.haslayer(scapy.IP):
       if pkt.haslayer(scapy.TCP) and pkt[scapy.TCP].dport in common_ports:
           device_violations[device_ip][0] = 1
       elif pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport in common_ports:
           device_violations[device_ip][0] = 1

# Rule 2: Excessive Traffic (DDoS)
def check_excessive_traffic(pkt, timestamp, device_ip, packet_counts, threshold=1000):
   packet_counts[timestamp] += 1
   if packet_counts[timestamp] > threshold:
       device_violations[device_ip][1] = 1

# Rule 3: Number of packets and packet size
def check_packet_count_and_size(pkt, packet_count, device_ip, size_threshold=1500, packet_threshold=1000):
   if len(pkt) > size_threshold:
       device_violations[device_ip][2] = 1
   packet_count += 1
   if packet_count > packet_threshold:
       device_violations[device_ip][2] = 1

# Rule 4: Unsolicited ARP replies
def check_unsolicited_arp(pkt, arp_request_set, arp_reply_set, device_ip):
   if pkt.haslayer(scapy.ARP):
       arp_op = pkt[scapy.ARP].op
       src_ip = pkt[scapy.ARP].psrc
       dest_ip = pkt[scapy.ARP].pdst
       if arp_op == 2: # ARP reply
           if (src_ip, dest_ip) not in arp_request_set:
               arp_reply_set.add((src_ip, dest_ip))
               device_violations[device_ip][3] = 1
       elif arp_op == 1: # ARP request
           arp_request_set.add((src_ip, dest_ip))

# Rule 5: Unusually large DNS responses
def check_large_dns_response(pkt, device_ip, size_threshold=512):
   if pkt.haslayer(scapy.UDP) and pkt[scapy.UDP].dport == 53:
       if pkt.haslayer(scapy.DNS) and len(pkt[scapy.DNS].payload) > size_threshold:
           device_violations[device_ip][4] = 1

# Rule 6: Excessive ICMP Echo requests
def check_icmp_echo_requests(pkt, icmp_count, device_ip, threshold=100):
   if pkt.haslayer(scapy.ICMP):
       if pkt[scapy.ICMP].type == 8: # Echo Request
           icmp_count += 1
           if icmp_count > threshold:
               device_violations[device_ip][5] = 1

# Rule 7: Excessive TCP SYN
def check_excessive_tcp_syn(pkt, syn_count, device_ip, threshold=100):
   if pkt.haslayer(scapy.TCP):
       if pkt[scapy.TCP].flags == "S": # SYN flag set
           syn_count += 1
           if syn_count > threshold:
               device_violations[device_ip][6] = 1

# Rule 8: IP scans excessive ports
def check_ip_scanning(pkt, ip_ports, device_ip, threshold=100):
   if pkt.haslayer(scapy.IP):
       src_ip = pkt[scapy.IP].src
       if pkt.haslayer(scapy.TCP) or pkt.haslayer(scapy.UDP):
           dest_port = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else pkt[scapy.UDP].dport
           ip_ports[src_ip].add(dest_port)
           if len(ip_ports[src_ip]) > threshold:
               device_violations[device_ip][7] = 1

# Malicious Device Probability (MDP) Calculation
def calculate_mdp(device_ip):
   violations = sum(device_violations[device_ip])
   mdp = (violations / 8) * 100
   return mdp

# Function to extract MAC address from ARP packet
def get_mac_address(device_ip, arp_packets):
   for pkt in arp_packets:
       if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].psrc == device_ip:
           return pkt[scapy.ARP].hwsrc
   return None

# Function to analyze PCAP and track device violations
def analyze_pcap(pcap_file):
   packets = scapy.rdpcap(pcap_file)

   # Track device violations (0=not violated, 1=violated)
   global device_violations
   device_violations = defaultdict(lambda: [0, 0, 0, 0, 0, 0, 0, 0])
   packet_counts = defaultdict(int) # Initialize packet count tracker
   arp_request_set = set()
   arp_reply_set = set()
   ip_ports = defaultdict(set)
   arp_packets = [] # For extracting MAC addresses
   packet_count = 0
   icmp_count = 0
   syn_count = 0

   # Process packets and track violations
   for pkt in packets:
       if pkt.haslayer(scapy.IP):
           device_ip = pkt[scapy.IP].src
           # Store ARP packets for later use to extract MAC addresses
           if pkt.haslayer(scapy.ARP):
               arp_packets.append(pkt)

           # Apply all rules to the current packet
           check_common_ports(pkt, device_ip)
           timestamp = int(time.time()) # Use time in seconds for Rule 2
           check_excessive_traffic(pkt, timestamp, device_ip, packet_counts) # Pass packet_counts here
           check_packet_count_and_size(pkt, packet_count, device_ip)
           check_unsolicited_arp(pkt, arp_request_set, arp_reply_
