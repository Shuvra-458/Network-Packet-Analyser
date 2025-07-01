# 📡 Network Packet Analyzer

A Python-based network traffic analysis tool with a **Streamlit web frontend**. It processes `.pcap` (packet capture) files and detects suspicious network activities using **8 predefined security rules**, calculates **Malicious Device Probability (MDP)**, and provides results in an interactive UI.

---

## 🚀 Features

- ✅ Analyze `.pcap` files (Wireshark captures)
- ✅ 8 rule-based detection checks (DDoS, ARP Spoofing, Port Scans, etc.)
- ✅ Malicious Device Probability (MDP) score for each device
- ✅ Interactive web frontend using **Streamlit**
- ✅ Export results as CSV
- ✅ Supports packaging as a standalone `.exe`

---

## 🛡️ Detection Rules

| Rule | Description |
|---- | ---- |
| **Rule 1** | Common Destination Ports (HTTP, HTTPS, DNS) |
| **Rule 2** | Excessive Traffic (Possible DDoS) |
| **Rule 3** | Large Packets / High Packet Counts |
| **Rule 4** | Unsolicited ARP Replies (ARP Spoofing) |
| **Rule 5** | Large DNS Responses (Exfiltration) |
| **Rule 6** | ICMP Echo Flood |
| **Rule 7** | TCP SYN Flood |
| **Rule 8** | Port Scanning Detection |

---

## 📂 Project Structure

Network-Packet-Analyser/
├── analyser.py # Backend logic (Scapy-based analysis)
├── streamlit_app.py # Streamlit frontend (Web UI)
├── requirements.txt # Python dependencies
├── .gitignore
└── sample.pcap # (Optional test PCAP file)

yaml
Copy
Edit

---

## 🖥️ Installation & Running Locally

### ✅ 1. Install Python packages:

```bash
pip install -r requirements.txt
Dependencies:

streamlit

pandas

scapy

(Optional for EXE build: pyinstaller)

✅ 2. Run the Streamlit frontend:
bash
Copy
Edit
streamlit run streamlit_app.py
Then open in browser:

arduino
Copy
Edit
http://localhost:8501
📈 Output Features
Device-wise rule violation table

MDP percentage for each IP

Rule-wise breakdown (all 8 rules)

CSV Export option

Full rule descriptions displayed on UI
