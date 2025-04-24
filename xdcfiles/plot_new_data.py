#!/usr/bin/env python3
import re
from collections import defaultdict
import json
import os
import sys
from http.server import HTTPServer, SimpleHTTPRequestHandler
import webbrowser
import threading

# Configuration
LEGIT_IP = "10.1.1.3"
ATTACK_IP = "10.1.1.4"
DEFAULT_LOGFILE = "lab8_traffic.txt"  # Default log file name

def extract_connection_counts(packets):
    successful_syns_legit = defaultdict(int)
    successful_syns_attack = defaultdict(int)
    unsuccessful_syns_legit = defaultdict(int)
    unsuccessful_syns_attack = defaultdict(int)

    connections = {}

    for packet in packets:
        key = (packet['src_ip'], packet['src_port'], packet['dst_ip'], packet['dst_port'])
        rev_key = (packet['dst_ip'], packet['dst_port'], packet['src_ip'], packet['src_port'])
        time_sec = int(packet['time'])

        flags = packet.get('flags')

        if flags == 'SYN':
            connections[key] = {
                'start_time': packet['time'],
                'state': 'SYN_SENT',
                'src_ip': packet['src_ip']
            }

        elif flags == 'SYN-ACK' and rev_key in connections:
            if connections[rev_key]['state'] == 'SYN_SENT':
                connections[rev_key]['state'] = 'SYN_RECEIVED'

        elif flags == 'ACK':
            if rev_key in connections and connections[rev_key]['state'] == 'SYN_RECEIVED':
                connections[rev_key]['state'] = 'ESTABLISHED'
                src_ip = connections[rev_key]['src_ip']
                if src_ip == LEGIT_IP:
                    successful_syns_legit[time_sec] += 1
                elif src_ip == ATTACK_IP:
                    successful_syns_attack[time_sec] += 1
                del connections[rev_key]

        elif flags in ['RST', 'FIN']:
            for key_variant in [key, rev_key]:
                if key_variant in connections:
                    if connections[key_variant]['state'] != 'ESTABLISHED':
                        src_ip = connections[key_variant]['src_ip']
                        if src_ip == LEGIT_IP:
                            unsuccessful_syns_legit[time_sec] += 1
                        elif src_ip == ATTACK_IP:
                            unsuccessful_syns_attack[time_sec] += 1
                    del connections[key_variant]

    for conn in connections.values():
        if conn['state'] != 'ESTABLISHED':
            src_ip = conn['src_ip']
            time_sec = int(conn['start_time'])
            if src_ip == LEGIT_IP:
                unsuccessful_syns_legit[time_sec] += 1
            elif src_ip == ATTACK_IP:
                unsuccessful_syns_attack[time_sec] += 1

    return {
        "unsuccessful_attack": dict(unsuccessful_syns_attack),
        "unsuccessful_legit": dict(unsuccessful_syns_legit),
        "successful_attack": dict(successful_syns_attack),
        "successful_legit": dict(successful_syns_legit)
    }

def parse_log_file(logfile_path):
    packet_list = []
    with open(logfile_path, encoding="utf-8", errors="ignore") as f:
        packet = {}
        for line in f:
            if line.startswith("Frame"):
                if packet:
                    packet_list.append(packet)
                packet = {}
            elif "Time" in line:
                match = re.search(r"(\d+\.\d+)", line)
                if match:
                    packet['time'] = float(match.group(1))
            elif "Src:" in line:
                match = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    packet['src_ip'] = match[0]
                    if len(match) > 1:
                        packet['dst_ip'] = match[1]
            elif "Src Port" in line:
                match = re.findall(r"(\d+)", line)
                if match:
                    packet['src_port'] = match[0]
                    if len(match) > 1:
                        packet['dst_port'] = match[1]
            elif "Flags" in line:
                if "SYN, ACK" in line:
                    packet['flags'] = 'SYN-ACK'
                elif "SYN" in line:
                    packet['flags'] = 'SYN'
                elif "ACK" in line:
                    packet['flags'] = 'ACK'
                elif "RST" in line:
                    packet['flags'] = 'RST'
                elif "FIN" in line:
                    packet['flags'] = 'FIN'
        if packet:
            packet_list.append(packet)

    results = extract_connection_counts(packet_list)
    return results

def generate_html(data):
    html_template = """
    <!DOCTYPE html>
    <html lang='en'>
    <head>
        <meta charset='UTF-8'>
        <title>SYN Flood Analysis</title>
        <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>
    </head>
    <body>
        <h2>SYN Flood Analysis Results</h2>
        <canvas id='chart' width='1200' height='400'></canvas>
        <script>
            const data = ANALYSIS_DATA_PLACEHOLDER;
            const labels = [...new Set([
                ...Object.keys(data.unsuccessful_attack),
                ...Object.keys(data.unsuccessful_legit),
                ...Object.keys(data.successful_attack),
                ...Object.keys(data.successful_legit)
            ])].sort((a,b) => a - b);

            const ctx = document.getElementById('chart').getContext('2d');
            const chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Unsuccessful Attack',
                            data: labels.map(t => data.unsuccessful_attack[t] || 0),
                            borderColor: 'red',
                            fill: false
                        },
                        {
                            label: 'Unsuccessful Legit',
                            data: labels.map(t => data.unsuccessful_legit[t] || 0),
                            borderColor: 'blue',
                            fill: false
                        },
                        {
                            label: 'Successful Attack',
                            data: labels.map(t => data.successful_attack[t] || 0),
                            borderColor: 'orange',
                            fill: false
                        },
                        {
                            label: 'Successful Legit',
                            data: labels.map(t => data.successful_legit[t] || 0),
                            borderColor: 'green',
                            fill: false
                        }
                    ]
                }
            });
        </script>
    </body>
    </html>
    """
    return html_template.replace("ANALYSIS_DATA_PLACEHOLDER", json.dumps(data))

def write_html(data):
    html = generate_html(data)
    output_file = "syn_flood_analysis.html"
    with open(output_file, "w") as f:
        f.write(html)
    return output_file

def start_server(html_file, port=8000):
    os.chdir(os.path.dirname(os.path.abspath(html_file)))
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Starting server at http://localhost:{port}")
    webbrowser.open(f"http://localhost:{port}/{os.path.basename(html_file)}")
    httpd.serve_forever()

def main():
    if len(sys.argv) > 1:
        logfile = sys.argv[1]
    else:
        logfile = DEFAULT_LOGFILE if os.path.exists(DEFAULT_LOGFILE) else input("Enter log file path: ")

    results = parse_log_file(logfile)
    html_file = write_html(results)
    start_server(html_file)

if __name__ == "__main__":
    main()
