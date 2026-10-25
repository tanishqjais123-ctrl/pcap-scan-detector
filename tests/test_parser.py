from scapy.all import Ether, IP, TCP, ARP, wrpcap
from pcap_scan_detector.parser import read_events


def test_tcp_syn_fields(tmp_path):
    p = tmp_path / "a.pcap"
    wrpcap(str(p), [Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=4000, dport=22, flags="S")])
    ev = list(read_events(str(p)))
    assert len(ev) == 1
    assert ev[0].src == "10.0.0.1"
    assert ev[0].dport == 22
    assert ev[0].flags == "S"


def test_non_ip_packet_skipped(tmp_path):
    p = tmp_path / "b.pcap"
    wrpcap(str(p), [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP()])
    assert list(read_events(str(p))) == []


def test_empty_file(tmp_path):
    p = tmp_path / "c.pcap"
    wrpcap(str(p), [])
    assert list(read_events(str(p))) == []
