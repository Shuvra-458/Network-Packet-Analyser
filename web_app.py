import streamlit as st
import pandas as pd
import analyser
import tempfile
import os

st.set_page_config(page_title="Network Packet Analyzer", layout="wide")

st.title("📡 Network Packet Analyzer")

st.header("🛡️ Detection Rules Explanation")

rule_descriptions = {
    "Rule 1": "✅ **Common Destination Ports:** Detects traffic to common ports like HTTP (80), HTTPS (443), or DNS (53).",
    "Rule 2": "📈 **Excessive Traffic (DDoS Detection):** Flags if a device sends an unusually high number of packets in a short time window.",
    "Rule 3": "📦 **Packet Size & Count:** Detects devices sending excessively large packets or too many packets (could indicate flooding).",
    "Rule 4": "❗ **Unsolicited ARP Replies:** Flags ARP replies that weren't requested (ARP spoofing indicator).",
    "Rule 5": "🔎 **Large DNS Responses:** Detects DNS replies larger than normal (possible data exfiltration).",
    "Rule 6": "📤 **Excessive ICMP Echo Requests:** Detects devices sending too many ping requests (ICMP flood).",
    "Rule 7": "🔑 **Excessive TCP SYN Packets:** Could indicate SYN flood attacks by tracking SYN request count.",
    "Rule 8": "🕵️ **IP Scanning Multiple Ports:** Detects port scan behavior (host contacting many different destination ports)."
}

for rule, description in rule_descriptions.items():
    st.markdown(f"**{rule}:** {description}")

st.markdown("---")

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap"])

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
        temp_file.write(uploaded_file.read())
        temp_path = temp_file.name

    st.info("Analyzing file... Please wait ⏳")

    try:
        analyser.analyze_pcap(temp_path)

        device_data = []
        for ip, violations in analyser.device_violations.items():
            mdp = analyser.calculate_mdp(ip)
            mac = analyser.get_mac_address(ip, analyser.arp_packets)
            row = [ip, mac or "N/A"] + violations + [f"{mdp:.2f}%"]
            device_data.append(row)

        columns = ["IP", "MAC", "Rule1", "Rule2", "Rule3", "Rule4", "Rule5", "Rule6", "Rule7", "Rule8", "MDP"]
        df = pd.DataFrame(device_data, columns=columns)

        st.success("✅ Analysis Completed!")

        st.dataframe(df, use_container_width=True)

        # Download as CSV
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Results as CSV",
            data=csv,
            file_name='network_analysis_results.csv',
            mime='text/csv',
        )

    except Exception as e:
        st.error(f"❌ Error analyzing file: {e}")

    finally:
        os.remove(temp_path)
