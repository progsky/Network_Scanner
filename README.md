```text
███████╗ █████╗ ███████╗████████╗     █████╗ ██████╗ ██████╗ 
██╔════╝██╔══██╗╚══███╔╝╚══██╔══╝    ██╔══██╗██╔══██╗██╔══██╗
███████╗███████║  ███╔╝    ██║       ███████║██████╔╝██████╔╝
╚════██║██╔══██║ ███╔╝     ██║       ██╔══██║██╔═══╝ ██╔═══╝ 
███████║██║  ██║███████╗   ██║       ██║  ██║██║     ██║     
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚═╝  ╚═╝╚═╝     ╚═╝     
           FAST  ARP  SCANNER


# Fast ARP Scanner

A simple and fast ARP network scanner written in Python.  
Automatically detects your local subnet (if not specified), supports multiple target ranges, parallel scanning, and outputs results in table, JSON, or CSV format.

## Requirements
- Python 3.6+
- scapy
- tabulate
- colorama

Install dependencies:
```bash
pip install -r requirements.txt


Usage

# Scan local subnet (auto-detect)
sudo python3 network_scanner.py

# Scan a specific range
sudo python3 network_scanner.py -t 192.168.0.1/24

# Multiple ranges
sudo python3 network_scanner.py -t 192.168.0.1/24,192.168.1.1/24

# JSON output
sudo python3 network_scanner.py -t 192.168.0.1/24 -f json

# CSV output
sudo python3 network_scanner.py -t 192.168.0.1/24 -f csv

# Parallel scanning with 4 threads
sudo python3 network_scanner.py -t 192.168.0.1/24 -p 4


Arguments

-t, --target — Target IP or IP range (CIDR). Multiple ranges separated by commas. If omitted, local subnet will be used.

-f, --format — Output format: table (default), json, csv.

-p, --parallel — Number of parallel scans (default: 1).

Notes

Requires root privileges to send ARP requests.

Works only within the local network segment.

On Windows, run from an elevated prompt or use WSL with scapy installed.
