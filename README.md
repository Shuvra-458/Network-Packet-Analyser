# Cybersecurity Packet Analyzer

## Overview
This project is a cybersecurity packet analyzer built using Python and Scapy. It analyzes network traffic from a PCAP file and detects potential malicious activity based on various predefined rules.

## Features
- Detects traffic on common ports (80, 443, 53)
- Identifies excessive traffic (DDoS detection)
- Flags unusually large packet sizes
- Detects unsolicited ARP replies
- Identifies large DNS responses
- Monitors excessive ICMP echo requests
- Detects excessive TCP SYN packets
- Identifies IP scanning activities
- Computes Malicious Device Probability (MDP) for each device

## Prerequisites
- Python 3.x
- Scapy library
- A valid PCAP file for analysis

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersecurity-packet-analyzer.git
   cd cybersecurity-packet-analyzer
   ```
2. Install dependencies:
   ```bash
   pip install scapy
   ```

## Usage
1. Run the script with a PCAP file:
   ```bash
   python analyze_pcap.py path/to/pcap/file.pcap
   ```
2. The script will process the packets and output detected security violations per device.

## Detection Rules
| Rule | Description |
|------|-------------|
| 1 | Detects common destination ports (80, 443, 53) |
| 2 | Detects excessive traffic (potential DDoS attack) |
| 3 | Identifies large packet sizes (>1500 bytes) |
| 4 | Detects unsolicited ARP replies |
| 5 | Flags large DNS responses (>512 bytes) |
| 6 | Detects excessive ICMP echo requests |
| 7 | Monitors excessive TCP SYN packets |
| 8 | Identifies excessive port scanning activity |

## Malicious Device Probability (MDP)
The script calculates an MDP score for each device based on the number of triggered rules.
MDP = (Number of violations / 8) * 100%

## Example Output
```bash
Device: 192.168.1.5
Violations: [1, 0, 1, 0, 0, 1, 0, 0]
Malicious Device Probability: 37.5%
```

## Troubleshooting
- Ensure the PCAP file is valid and contains network packets.
- Run the script with administrator/root privileges if required.
- Verify Scapy installation: `pip show scapy`.


## Author
Shuvrajyoti
[Shuvra-458](https://github.com/Shuvra-458)

