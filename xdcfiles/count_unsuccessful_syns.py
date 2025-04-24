#!/usr/bin/env python3
from collections import defaultdict
import re
import sys

# Configuration
LEGIT_IP = "10.1.1.3"
ATTACK_IP = "10.1.1.4"
LOGFILE = "lab8_traffic.txt"
DEBUG = True  # Set to True to print debug information about the first few packets

# Regular expressions for parsing
frame_pattern = re.compile(r'Frame (\d+):')
time_pattern = re.compile(r'No\.\s+Time\s+Source\s+Destination\s+Protocol\s+Length\s+Info\n\s+\d+\s+(\d+\.\d+)')
src_pattern = re.compile(r'Internet Protocol Version 4, Src: (\d+\.\d+\.\d+\.\d+)')
dst_pattern = re.compile(r'Internet Protocol Version 4, Src: \d+\.\d+\.\d+\.\d+, Dst: (\d+\.\d+\.\d+\.\d+)')
port_pattern = re.compile(r'Transmission Control Protocol, Src Port: (\d+), Dst Port: (\d+)')
flag_pattern = re.compile(r'\[([A-Z, ]+)\]')

# Data structures
connections = defaultdict(lambda: {"syn_count": 0, "times": [], "established": False, "first_syn_time": None})
unsuccessful_syns_legit = defaultdict(int)
unsuccessful_syns_attack = defaultdict(int)
all_packets = []
first_time = None
earliest_syn_time = float('inf')

def process_packet_group(packet_lines):
    """Process a group of lines representing a single packet."""
    if not packet_lines:
        return None
    
    packet_text = '\n'.join(packet_lines)
    
    # Extract frame number
    frame_match = frame_pattern.search(packet_text)
    frame_num = int(frame_match.group(1)) if frame_match else 0
    
    # Extract time
    time_match = time_pattern.search(packet_text)
    if not time_match:
        # Try to find time in other format
        alt_time_match = re.search(r'Time\s+(\d+\.\d+)', packet_text)
        if alt_time_match:
            time = float(alt_time_match.group(1))
        else:
            return None
    else:
        time = float(time_match.group(1))
    
    # Extract source and destination IPs
    src_match = src_pattern.search(packet_text)
    dst_match = dst_pattern.search(packet_text)
    if not src_match or not dst_match:
        return None
    src_ip = src_match.group(1)
    dst_ip = dst_match.group(1)
    
    # Extract ports
    port_match = port_pattern.search(packet_text)
    if not port_match:
        return None
    src_port = port_match.group(1)
    dst_port = port_match.group(2)
    
    # Determine packet type
    packet_type = None
    flag_match = flag_pattern.search(packet_text)
    
    if flag_match:
        flags = flag_match.group(1)
        if "SYN" in flags and "ACK" in flags:
            packet_type = "SYN-ACK"
        elif "SYN" in flags:
            packet_type = "SYN"
        elif "ACK" in flags and "SYN" not in flags:
            packet_type = "ACK"
        elif "RST" in flags:
            packet_type = "RST"
        elif "FIN" in flags:
            packet_type = "FIN"
    
    return {
        "frame": frame_num,
        "time": time,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "type": packet_type,
        "second": int(time)
    }

# Process the log file
print("Analyzing log file...")
parse_count = 0
syn_count = 0
total_processed = 0

with open(LOGFILE, encoding="utf-8", errors="ignore") as f:
    current_packet_lines = []
    
    for line in f:
        # Start of a new packet
        if line.startswith("Frame "):
            if current_packet_lines:
                total_processed += 1
                packet = process_packet_group(current_packet_lines)
                
                if total_processed % 10000 == 0:
                    print(f"Processed {total_processed} packets...")
                
                if packet:
                    parse_count += 1
                    
                    # Keep track of first packet time
                    if first_time is None:
                        first_time = packet["time"]
                    
                    if packet["type"] == "SYN":
                        syn_count += 1
                        if packet["time"] < earliest_syn_time:
                            earliest_syn_time = packet["time"]
                    
                    # Process the packet for SYN flood analysis
                    if packet["type"]:
                        conn_key = (packet["src_ip"], packet["src_port"], packet["dst_ip"], packet["dst_port"])
                        rev_conn_key = (packet["dst_ip"], packet["dst_port"], packet["src_ip"], packet["src_port"])
                        
                        if packet["type"] == "SYN":
                            if conn_key not in connections or connections[conn_key]["syn_count"] == 0:
                                connections[conn_key]["first_syn_time"] = packet["time"]
                            
                            connections[conn_key]["syn_count"] += 1
                            connections[conn_key]["times"].append(packet["time"])
                        
                        elif packet["type"] == "SYN-ACK":
                            if rev_conn_key in connections:
                                connections[rev_conn_key]["syn_ack_received"] = True
                        
                        elif packet["type"] == "ACK":
                            if rev_conn_key in connections and connections[rev_conn_key].get("syn_ack_received"):
                                connections[rev_conn_key]["established"] = True
                        
                        # Connection termination or reset
                        elif packet["type"] in ["RST", "FIN"]:
                            # Check if this is an unsuccessful connection (multiple SYNs without establishment)
                            if conn_key in connections and connections[conn_key]["syn_count"] > 1 and not connections[conn_key]["established"]:
                                src_ip = conn_key[0]
                                for t in connections[conn_key]["times"]:
                                    sec = int(t)
                                    if src_ip == LEGIT_IP:
                                        unsuccessful_syns_legit[sec] += 1
                                    elif src_ip == ATTACK_IP:
                                        unsuccessful_syns_attack[sec] += 1
                            
                            # Clean up the connection
                            if conn_key in connections:
                                del connections[conn_key]
                    
                    # Store first 10 packets for debugging
                    if DEBUG and len(all_packets) < 20:
                        all_packets.append(packet)
            
            # Start collecting the new packet
            current_packet_lines = [line]
        else:
            # Continue collecting the current packet
            current_packet_lines.append(line)

# Process the last packet if there is one
if current_packet_lines:
    packet = process_packet_group(current_packet_lines)
    if packet and packet["type"]:
        conn_key = (packet["src_ip"], packet["src_port"], packet["dst_ip"], packet["dst_port"])
        if packet["type"] == "SYN":
            connections[conn_key]["syn_count"] += 1
            connections[conn_key]["times"].append(packet["time"])

# Process remaining connections that didn't get explicit termination
for conn_key, data in list(connections.items()):
    if data["syn_count"] > 1 and not data.get("established", False):
        src_ip = conn_key[0]
        for time in data["times"]:
            second = int(time)
            if src_ip == LEGIT_IP:
                unsuccessful_syns_legit[second] += 1
            elif src_ip == ATTACK_IP:
                unsuccessful_syns_attack[second] += 1

# Print debug information
if DEBUG:
    print("\nParsing Summary:")
    print(f"Total packets processed: {total_processed}")
    print(f"Successfully parsed packets: {parse_count}")
    print(f"SYN packets found: {syn_count}")
    print(f"First packet time: {first_time}")
    print(f"Earliest SYN packet time: {earliest_syn_time}")
    
    print("\nFirst few packets:")
    for i, packet in enumerate(all_packets):
        print(f"{i+1}. Frame {packet['frame']} - Time: {packet['time']} - {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} - Type: {packet['type']}")
    
    print("\nFirst few connections with multiple SYNs:")
    count = 0
    for conn_key, data in connections.items():
        if data["syn_count"] > 1:
            src_ip, src_port, dst_ip, dst_port = conn_key
            print(f"Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            print(f"  SYN count: {data['syn_count']}")
            print(f"  First SYN time: {data['first_syn_time']}")
            print(f"  Established: {data['established']}")
            count += 1
            if count >= 5:
                break

# Print results
print("\nTime (s) | Unsuccessful Legit SYNs | Unsuccessful Attack SYNs")
all_seconds = sorted(set(unsuccessful_syns_legit) | set(unsuccessful_syns_attack))
for sec in all_seconds:
    legit = unsuccessful_syns_legit.get(sec, 0)
    attack = unsuccessful_syns_attack.get(sec, 0)
    print(f"{sec:<9} | {legit:<24} | {attack}")

# Print totals
total_legit = sum(unsuccessful_syns_legit.values())
total_attack = sum(unsuccessful_syns_attack.values())
print("\nTotals:")
print(f"Unsuccessful Legit SYNs: {total_legit}")
print(f"Unsuccessful Attack SYNs: {total_attack}")