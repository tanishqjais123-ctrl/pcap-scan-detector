"""Builds a small synthetic port-scan capture (no real traffic or private data)."""
from scapy.all import Ether, IP, TCP, wrpcap

packets = []
for i in range(30):
    p = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=1000 + i, flags="S")
    p.time = 1000 + i * 0.1
    packets.append(p)
wrpcap("examples/demo_scan.pcap", packets)
