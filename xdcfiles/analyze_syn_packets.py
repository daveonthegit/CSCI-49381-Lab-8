import re
from datetime import datetime

pcap_txt_path = "lab8_traffic.txt"  # Update if needed

# Regex to extract useful fields
pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+).*IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]+)\]')

connections = {}

with open(pcap_txt_path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        match = pattern.search(line)
        if match:
            ts, src_ip, src_port, dst_ip, dst_port, flags = match.groups()
            key = (src_ip, src_port, dst_ip, dst_port)
            timestamp = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")

            if "S" in flags and "A" not in flags:  # SYN but not SYN-ACK
                connections[key] = {"timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip}

# Output all SYN packets seen
print("SYN Packet Log")
print("Time\t\t\tSource IP\tDest IP")
for key, data in connections.items():
    print(f"{data['timestamp']}\t{data['src_ip']} -> {data['dst_ip']}")
