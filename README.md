📡 Network Packet Analyzer
A network traffic analysis tool that reads .pcap (packet capture) files, detects possible malicious activity based on multiple detection rules, and presents the results in a user-friendly Streamlit web frontend.

✅ Features
📥 Upload and Analyze PCAP files

🛡️ 8 Built-in Detection Rules for common network threats

📊 MDP (Malicious Device Probability) calculation per device

📃 Results shown in interactive DataFrames

📤 Export results as CSV

🌐 Streamlit Web UI

🛡️ Detection Rules
Rule No	Detection Logic

Rule 1	Common Destination Ports: Detects traffic on HTTP (80), HTTPS (443), DNS (53)

Rule 2	Excessive Traffic (DDoS Detection): Too many packets in short time

Rule 3	Packet Size & Count: Large packets or too many packets

Rule 4	Unsolicited ARP Replies: Possible ARP spoofing

Rule 5	Large DNS Responses: Possible data exfiltration

Rule 6	Excessive ICMP Echo Requests: ICMP flooding

Rule 7	Excessive TCP SYN Packets: SYN flood detection

Rule 8	IP Scanning Multiple Ports: Possible port scanning behavior

🖥️ Requirements
Install all required Python packages:
pip install -r requirements.txt
Main libraries used:

scapy
pandas
streamlit

🚀 Running the Streamlit Frontend
streamlit run streamlit_app.py
Then open:
http://localhost:8501



