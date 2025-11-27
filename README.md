Network Sniffer (Python + Scapy)

A lightweight network-packet sniffing tool built using Python and Scapy.
It captures live traffic, prints structured packet details, and saves the full capture to a .pcap file for later analysis with tools like Wireshark.

Features

Capture packets from any network interface

Real-time packet details:

IP headers
TCP/UDP/ICMP data
Raw payload preview
Save captured traffic to capture.pcap
Infinite or fixed-count capture
Simple callback-based design

Requirements :

Python 3.x
Scapy library
Install:
pip install scapy


Note: Packet sniffing typically requires administrator/root privileges.

Usage
Run the sniffer
sudo python3 sniffer.py

Configuration Variables

Inside the script:

INTERFACE = None        # Set "eth0", "wlan0", or leave None for default
COUNT = 0               # 0 = capture until Ctrl+C
SAVE_PCAP = "capture.pcap"

Optional: Add a BPF Filter

Examples:

filter="tcp port 80"
filter="udp port 53"
filter="icmp"
filter="port 443"

Modify inside:
sniff(..., filter="your_filter_here")

Output Example
============================================================
Summary: IP / TCP ...
Length: 74
IP -> src: 192.168.1.5  dst: 142.251.36.3  ttl: 64
TCP -> sport: 52510  dport: 443  flags: PA
Payload (preview): GET / HTTP/1.1


After stopping (Ctrl+C):

Saved 128 packets to capture.pcap
Analyze the Capture

Open capture.pcap in:

Wireshark
tcpdump
Scapy (rdpcap())
Project Structure
network-sniffer/
│
├── sniffer.py
├── capture.pcap        # created after running
└── README.md

Legal Notice :

This tool is intended only for authorized security testing, research, and network diagnostics.
Do NOT sniff traffic on networks you do not own or have explicit permission to analyze.
Unauthorized packet capture is illegal in many countries.
