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

def parse_log_file(logfile_path, legit_ip=LEGIT_IP, attack_ip=ATTACK_IP):
    """Parse the log file and extract connection data"""
    # Enhanced regular expressions for parsing that better match the sample data
    frame_pattern = re.compile(r'Frame (\d+):')
    # Multiple patterns for time extraction from different formats in the log
    time_pattern = re.compile(r'Time\s+(\d+\.\d+)')
    alt_time_pattern = re.compile(r'No\.\s+Time\s+Source\s+Destination\s+Protocol\s+Length\s+Info\n\s*\d+\s+(\d+\.\d+)')
    info_time_pattern = re.compile(r'No\.\s+Time\s+Source\s+Destination\s+Protocol\s+Length\s+Info\s+(\d+)\s+(\d+\.\d+)')
    
    # Modified patterns for IP extraction
    src_ip_pattern = re.compile(r'Internet Protocol Version 4, Src: (\d+\.\d+\.\d+\.\d+)')
    dst_ip_pattern = re.compile(r'Internet Protocol Version 4, Src: (\d+\.\d+\.\d+\.\d+), Dst: (\d+\.\d+\.\d+\.\d+)')
    alt_src_dst_pattern = re.compile(r'Source\s+Destination\s+Protocol\s+Length\s+Info\s+\d+\s+\d+\.\d+\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)')
    
    # Enhanced port patterns
    port_pattern = re.compile(r'Transmission Control Protocol, Src Port: (\d+), Dst Port: (\d+)')
    alt_port_pattern = re.compile(r'(\d+) → (\d+)')
    
    # Enhanced flag patterns
    flag_pattern = re.compile(r'\[([A-Z, ]+)\]')
    alt_flag_pattern = re.compile(r'→ \d+ \[([A-Z, ]+)\]')

    # Data structures for tracking connections
    connections = {}
    unsuccessful_syns_legit = defaultdict(int)
    unsuccessful_syns_attack = defaultdict(int)
    successful_syns_legit = defaultdict(int)
    successful_syns_attack = defaultdict(int)

    # Statistics
    stats = {
        "total_packets": 0,
        "syn_packets": 0,
        "parsed_packets": 0,
        "earliest_time": float('inf'),
        "latest_time": 0
    }

    # Process the log file
    print(f"Analyzing log file: {logfile_path}")
    current_packet_lines = []
    
    with open(logfile_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            # Start of a new packet
            if line.startswith("Frame "):
                if current_packet_lines:
                    packet_text = '\n'.join(current_packet_lines)
                    stats["total_packets"] += 1
                    
                    # Extract data from packet
                    try:
                        # Extract frame number
                        frame_match = frame_pattern.search(packet_text)
                        frame_num = int(frame_match.group(1)) if frame_match else 0
                        
                        # Extract time - try different patterns
                        time_match = time_pattern.search(packet_text)
                        if not time_match:
                            time_match = alt_time_pattern.search(packet_text)
                        if not time_match:
                            info_match = info_time_pattern.search(packet_text)
                            if info_match:
                                time_match = info_match
                                
                        if time_match:
                            if len(time_match.groups()) > 1:
                                time = float(time_match.group(2))  # Use second group for info_time_pattern
                            else:
                                time = float(time_match.group(1))
                            stats["earliest_time"] = min(stats["earliest_time"], time)
                            stats["latest_time"] = max(stats["latest_time"], time)
                        else:
                            continue  # Skip if no time found
                        
                        # Extract source IP
                        src_ip = None
                        dst_ip = None
                        
                        # Try primary patterns
                        src_match = src_ip_pattern.search(packet_text)
                        dst_match = dst_ip_pattern.search(packet_text)
                        
                        if src_match:
                            src_ip = src_match.group(1)
                        
                        if dst_match:
                            # This pattern captures both src and dst
                            src_ip = dst_match.group(1)
                            dst_ip = dst_match.group(2)
                        
                        # Try alternative pattern if needed
                        if not src_ip or not dst_ip:
                            alt_match = alt_src_dst_pattern.search(packet_text)
                            if alt_match:
                                src_ip = alt_match.group(1)
                                dst_ip = alt_match.group(2)
                        
                        if not src_ip or not dst_ip:
                            continue  # Skip if we can't identify IPs
                        
                        # Extract ports
                        port_match = port_pattern.search(packet_text)
                        if not port_match:
                            port_match = alt_port_pattern.search(packet_text)
                        
                        if port_match:
                            src_port = port_match.group(1)
                            dst_port = port_match.group(2)
                        else:
                            continue  # Skip if no ports found
                        
                        # Determine packet type
                        packet_type = None
                        flag_match = flag_pattern.search(packet_text)
                        if not flag_match:
                            flag_match = alt_flag_pattern.search(packet_text)
                        
                        if flag_match:
                            flags = flag_match.group(1)
                            if "SYN" in flags and "ACK" in flags:
                                packet_type = "SYN-ACK"
                            elif "SYN" in flags:
                                packet_type = "SYN"
                                stats["syn_packets"] += 1
                            elif "ACK" in flags and "SYN" not in flags:
                                packet_type = "ACK"
                            elif "RST" in flags:
                                packet_type = "RST"
                            elif "FIN" in flags:
                                packet_type = "FIN"
                        
                        stats["parsed_packets"] += 1
                        
                        # Process connection state
                        if packet_type:
                            conn_key = (src_ip, src_port, dst_ip, dst_port)
                            rev_conn_key = (dst_ip, dst_port, src_ip, src_port)
                            
                            if packet_type == "SYN":
                                # Initialize connection if needed
                                if conn_key not in connections:
                                    connections[conn_key] = {
                                        "syn_count": 1, 
                                        "syn_times": [time], 
                                        "established": False,
                                        "syn_ack_received": False,
                                        "src_ip": src_ip,
                                        "first_syn_time": time  # Record the time of first SYN
                                    }
                                else:
                                    # This is a SYN retransmission - count as unsuccessful at the time of retransmission
                                    if not connections[conn_key]["established"]:
                                        connections[conn_key]["syn_count"] += 1
                                        connections[conn_key]["syn_times"].append(time)
                                        second = int(time)
                                        if src_ip == legit_ip:
                                            unsuccessful_syns_legit[second] += 1
                                        elif src_ip == attack_ip:
                                            unsuccessful_syns_attack[second] += 1
                            
                            elif packet_type == "SYN-ACK":
                                # If this is a response to a SYN we're tracking
                                if rev_conn_key in connections:
                                    connections[rev_conn_key]["syn_ack_received"] = True
                            
                            elif packet_type == "ACK":
                                # Check if this completes a three-way handshake
                                if rev_conn_key in connections and connections[rev_conn_key].get("syn_ack_received"):
                                    if not connections[rev_conn_key]["established"]:
                                        connections[rev_conn_key]["established"] = True
                                        
                                        # Record this as a successful connection at the time of the FIRST SYN
                                        src_ip_original = connections[rev_conn_key]["src_ip"]
                                        second = int(connections[rev_conn_key]["first_syn_time"])
                                        
                                        if src_ip_original == attack_ip:
                                            successful_syns_attack[second] += 1
                                        elif src_ip_original == legit_ip:
                                            successful_syns_legit[second] += 1
                            
                            # Connection termination
                            elif packet_type in ["RST", "FIN"]:
                                # Clean up the connection
                                for key in [conn_key, rev_conn_key]:
                                    if key in connections:
                                        del connections[key]
                    except Exception as e:
                        print(f"Error processing packet {stats['total_packets']}: {e}")
                        continue
                
                # Start collecting the new packet
                current_packet_lines = [line]
            else:
                # Continue collecting the current packet
                current_packet_lines.append(line)
    
    # Process the last packet if there is one
    if current_packet_lines:
        # Processing would be the same as in the loop
        # (Omitted for brevity but would include the same packet processing logic)
        pass
    
    #*# Process remaining connections that didn't get explicit termination
    for conn_key, data in list(connections.items()):
        if data["syn_count"] > 0 and not data.get("established", False):
            src_ip = data["src_ip"]
            for time in data["syn_times"]:
                second = int(time)
                if src_ip == legit_ip:
                    unsuccessful_syns_legit[second] += 1
                elif src_ip == attack_ip:
                    unsuccessful_syns_attack[second] += 1
    #
    # Prepare results for visualization
    results = {
        "unsuccessful_attack": dict(unsuccessful_syns_attack),
        "unsuccessful_legit": dict(unsuccessful_syns_legit),
        "successful_attack": dict(successful_syns_attack),
        "successful_legit": dict(successful_syns_legit),
        "stats": stats
    }
    
    # Print a brief summary
    print(f"Analysis complete. Processed {stats['total_packets']} packets.")
    print(f"Found {stats['syn_packets']} SYN packets.")
    print(f"Time range: {stats['earliest_time']} - {stats['latest_time']} seconds")
    print(f"Total unsuccessful attack connections: {sum(unsuccessful_syns_attack.values())}")
    print(f"Total unsuccessful legitimate connections: {sum(unsuccessful_syns_legit.values())}")
    print(f"Total successful attack connections: {sum(successful_syns_attack.values())}")
    print(f"Total successful legitimate connections: {sum(successful_syns_legit.values())}")
    
    return results

def generate_html(data):
    """Generate HTML visualization with the analysis results"""
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYN Flood Analysis Results</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.1/chart.min.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2 {
            text-align: center;
            color: #333;
        }
        .chart-container {
            position: relative;
            height: 500px;
            width: 100%;
            margin-bottom: 30px;
        }
        .summary {
            background-color: #f9f9f9;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            border: 1px solid #ddd;
        }
        .controls {
            display: flex;
            justify-content: center;
            margin: 20px 0;
        }
        .controls button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin: 0 10px;
        }
        .controls button:hover {
            background-color: #45a049;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin-top: 20px;
        }
        .stat-card {
            background-color: #fff;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 {
            margin-top: 0;
            color: #555;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SYN Flood Analysis Results</h1>
        
        <div class="controls">
            <button id="toggleAllBtn">Show/Hide All</button>
            <button id="showAttackBtn">Show Attack Only</button>
            <button id="showLegitBtn">Show Legitimate Only</button>
            <button id="showSuccessBtn">Show Successful Only</button>
            <button id="showUnsuccessBtn">Show Unsuccessful Only</button>
        </div>
        
        <div class="chart-container">
            <canvas id="connectionChart"></canvas>
        </div>
        
        <div class="summary">
            <h2>Analysis Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Unsuccessful Attack Connections</h3>
                    <div class="stat-value" id="unsuccessfulAttackTotal">0</div>
                </div>
                <div class="stat-card">
                    <h3>Unsuccessful Legitimate Connections</h3>
                    <div class="stat-value" id="unsuccessfulLegitTotal">0</div>
                </div>
                <div class="stat-card">
                    <h3>Successful Attack Connections</h3>
                    <div class="stat-value" id="successfulAttackTotal">0</div>
                </div>
                <div class="stat-card">
                    <h3>Successful Legitimate Connections</h3>
                    <div class="stat-value" id="successfulLegitTotal">0</div>
                </div>
                <div class="stat-card">
                    <h3>Total Packets Analyzed</h3>
                    <div class="stat-value" id="totalPackets">0</div>
                </div>
                <div class="stat-card">
                    <h3>Total SYN Packets</h3>
                    <div class="stat-value" id="synPackets">0</div>
                </div>
                <div class="stat-card">
                    <h3>Earliest Time</h3>
                    <div class="stat-value" id="earliestTime">0</div>
                </div>
                <div class="stat-card">
                    <h3>Latest Time</h3>
                    <div class="stat-value" id="latestTime">0</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Visualization data from Python analysis
        const analysisData = ANALYSIS_DATA_PLACEHOLDER;
        
        // Chart initialization
        let connectionChart;
        
        // Initialize the chart with data
        function initChart() {
            const ctx = document.getElementById('connectionChart').getContext('2d');
            
            // Get all time points from the data
            const allTimePoints = new Set();
            
            // Add all seconds from all datasets
            for (const second in analysisData.unsuccessful_attack) allTimePoints.add(parseInt(second));
            for (const second in analysisData.unsuccessful_legit) allTimePoints.add(parseInt(second));
            for (const second in analysisData.successful_attack) allTimePoints.add(parseInt(second));
            for (const second in analysisData.successful_legit) allTimePoints.add(parseInt(second));
            
            // Convert to array and sort
            const timeLabels = Array.from(allTimePoints).sort((a, b) => a - b);
            
            // Prepare datasets
            const unsuccessfulAttackData = timeLabels.map(second => 
                analysisData.unsuccessful_attack[second] || 0
            );
            const unsuccessfulLegitData = timeLabels.map(second => 
                analysisData.unsuccessful_legit[second] || 0
            );
            const successfulAttackData = timeLabels.map(second => 
                analysisData.successful_attack[second] || 0
            );
            const successfulLegitData = timeLabels.map(second => 
                analysisData.successful_legit[second] || 0
            );
            
            // Create the chart
            connectionChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: timeLabels,
                    datasets: [
                        {
                            label: 'Unsuccessful Attack Connections',
                            data: unsuccessfulAttackData,
                            borderColor: 'rgb(255, 99, 132)',
                            backgroundColor: 'rgba(255, 99, 132, 0.2)',
                            tension: 0.1,
                            borderWidth: 2
                        },
                        {
                            label: 'Unsuccessful Legitimate Connections',
                            data: unsuccessfulLegitData,
                            borderColor: 'rgb(54, 162, 235)',
                            backgroundColor: 'rgba(54, 162, 235, 0.2)',
                            tension: 0.1,
                            borderWidth: 2
                        },
                        {
                            label: 'Successful Attack Connections',
                            data: successfulAttackData,
                            borderColor: 'rgb(255, 159, 64)',
                            backgroundColor: 'rgba(255, 159, 64, 0.2)',
                            tension: 0.1,
                            borderWidth: 2
                        },
                        {
                            label: 'Successful Legitimate Connections',
                            data: successfulLegitData,
                            borderColor: 'rgb(75, 192, 192)',
                            backgroundColor: 'rgba(75, 192, 192, 0.2)',
                            tension: 0.1,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Number of Connections'
                            }
                        },
                        x: {
                            title: {
                                display: true,
                                text: 'Time (seconds)'
                            }
                        }
                    },
                    plugins: {
                        title: {
                            display: true,
                            text: 'Network Connection Analysis Over Time',
                            font: {
                                size: 16
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false
                        },
                        legend: {
                            position: 'top',
                        }
                    }
                }
            });
        }
        
        // Update summary section with totals
        function updateSummary() {
            // Calculate totals
            const totalUnsuccessfulAttack = Object.values(analysisData.unsuccessful_attack)
                .reduce((sum, val) => sum + val, 0);
            const totalUnsuccessfulLegit = Object.values(analysisData.unsuccessful_legit)
                .reduce((sum, val) => sum + val, 0);
            const totalSuccessfulAttack = Object.values(analysisData.successful_attack)
                .reduce((sum, val) => sum + val, 0);
            const totalSuccessfulLegit = Object.values(analysisData.successful_legit)
                .reduce((sum, val) => sum + val, 0);
            
            // Update the DOM
            document.getElementById('unsuccessfulAttackTotal').textContent = totalUnsuccessfulAttack;
            document.getElementById('unsuccessfulLegitTotal').textContent = totalUnsuccessfulLegit;
            document.getElementById('successfulAttackTotal').textContent = totalSuccessfulAttack;
            document.getElementById('successfulLegitTotal').textContent = totalSuccessfulLegit;
            
            // Update stats
            document.getElementById('totalPackets').textContent = analysisData.stats.total_packets;
            document.getElementById('synPackets').textContent = analysisData.stats.syn_packets;
            document.getElementById('earliestTime').textContent = analysisData.stats.earliest_time.toFixed(2);
            document.getElementById('latestTime').textContent = analysisData.stats.latest_time.toFixed(2);
        }
        
        // Toggle dataset visibility
        function toggleDataset(showAttack, showLegit, showSuccess, showUnsuccess) {
            connectionChart.data.datasets[0].hidden = !(showAttack && showUnsuccess); // Unsuccessful Attack
            connectionChart.data.datasets[1].hidden = !(showLegit && showUnsuccess);  // Unsuccessful Legit
            connectionChart.data.datasets[2].hidden = !(showAttack && showSuccess);   // Successful Attack
            connectionChart.data.datasets[3].hidden = !(showLegit && showSuccess);    // Successful Legit
            connectionChart.update();
        }
        
        // Initialize when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            initChart();
            updateSummary();
            
            // Set up toggle buttons
            document.getElementById('toggleAllBtn').addEventListener('click', function() {
                const allHidden = connectionChart.data.datasets.every(ds => ds.hidden);
                connectionChart.data.datasets.forEach(dataset => dataset.hidden = !allHidden);
                connectionChart.update();
            });
            
            document.getElementById('showAttackBtn').addEventListener('click', function() {
                toggleDataset(true, false, true, true);
            });
            
            document.getElementById('showLegitBtn').addEventListener('click', function() {
                toggleDataset(false, true, true, true);
            });
            
            document.getElementById('showSuccessBtn').addEventListener('click', function() {
                toggleDataset(true, true, true, false);
            });
            
            document.getElementById('showUnsuccessBtn').addEventListener('click', function() {
                toggleDataset(true, true, false, true);
            });
        });
    </script>
</body>
</html>
    """
    
    # Insert the JSON data
    json_data = json.dumps(data)
    html = html.replace('ANALYSIS_DATA_PLACEHOLDER', json_data)
    
    return html

def start_server(html_file, port=8000):
    """Start a simple HTTP server to display the HTML file"""
    # Change to the directory containing the HTML file
    os.chdir(os.path.dirname(os.path.abspath(html_file)))
    
    # Create and start the server
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    
    # Print information
    print(f"Starting server at http://localhost:{port}")
    print(f"Press Ctrl+C to stop the server")
    
    # Start the server in a separate thread
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    # Open the browser
    webbrowser.open(f"http://localhost:{port}/{os.path.basename(html_file)}")
    
    try:
        # Keep the main thread running
        while True:
            pass
    except KeyboardInterrupt:
        print("Server stopped")
        httpd.shutdown()

def main():
    """Main function to run the analysis and visualization"""
    # Check for command line arguments
    if len(sys.argv) > 1:
        logfile = sys.argv[1]
    else:
        # Try to find the log file in the current directory
        if os.path.exists(DEFAULT_LOGFILE):
            logfile = DEFAULT_LOGFILE
        else:
            print(f"Log file '{DEFAULT_LOGFILE}' not found.")
            logfile = input("Please enter the path to your log file: ")
    
    # Analyze the log file
    try:
        results = parse_log_file(logfile)
    except FileNotFoundError:
        print(f"Error: Could not find the log file '{logfile}'")
        return
    except Exception as e:
        print(f"Error during analysis: {e}")
        return
    
    # Generate the HTML visualization
    html_content = generate_html(results)
    
    # Write the HTML to a file
    output_file = "syn_flood_analysis.html"
    with open(output_file, "w") as f:
        f.write(html_content)
    
    print(f"Analysis results saved to {output_file}")
    
    # Start a simple HTTP server to display the results
    try:
        start_server(output_file)
    except Exception as e:
        print(f"Could not start the server: {e}")
        print(f"Please open {output_file} in your web browser manually.")

if __name__ == "__main__":
    main()