#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

# Configuration
INTERFACE = None   # e.g. "eth0" or "wlan0". None -> default interface
COUNT = 0          # 0 -> infinite until ctrl-c
SAVE_PCAP = "capture.pcap"  # file to save

captured_packets = []

def packet_callback(pkt):
    # Save every packet for later writing
    captured_packets.append(pkt)

    # Basic info
    proto = pkt.summary()
    length = len(pkt)
    print("="*60)
    print("Summary:", proto)
    print("Length:", length)

    # If IP layer present
    if IP in pkt:
        ip = pkt[IP]
        print(f"IP -> src: {ip.src}  dst: {ip.dst}  ttl: {ip.ttl}")

    # TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        sport = tcp.sport
        dport = tcp.dport
        flags = tcp.flags
        print(f"TCP -> sport: {sport}  dport: {dport}  flags: {flags}")

    # UDP
    if UDP in pkt:
        udp = pkt[UDP]
        print(f"UDP -> sport: {udp.sport}  dport: {udp.dport}")

    # ICMP
    if ICMP in pkt:
        icmp = pkt[ICMP]
        print(f"ICMP -> type: {icmp.type}  code: {icmp.code}")

    # Raw payload (print safely first 100 bytes)
    if Raw in pkt:
        raw_bytes = pkt[Raw].load
        try:
            printable = raw_bytes.decode('utf-8', errors='replace')
        except:
            printable = str(raw_bytes)
        print("Payload (preview):", printable[:200])

    # For detailed view:
    # pkt.show()

try:
    print("Starting sniffing... Press Ctrl+C to stop.")
    # Example with BPF filter to only capture HTTP (tcp port 80): filter="tcp port 80"
    sniff(iface=INTERFACE, prn=packet_callback, count=COUNT, filter=None)
except KeyboardInterrupt:
    print("\nStopped by user, saving pcap...")

# Save captured packets to pcap
if captured_packets:
    wrpcap(SAVE_PCAP, captured_packets)
    print(f"Saved {len(captured_packets)} packets to {SAVE_PCAP}")
else:
    print("No packets captured.")