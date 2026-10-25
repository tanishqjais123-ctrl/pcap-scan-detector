from dataclasses import dataclass
from scapy.all import PcapReader, IP, TCP, UDP


@dataclass
class Event:
    time: float
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None
    flags: str | None


def read_events(path):
    with PcapReader(path) as reader:
        for pkt in reader:
            if IP not in pkt:
                continue
            ip = pkt[IP]
            if TCP in pkt:
                t = pkt[TCP]
                yield Event(float(pkt.time), ip.src, ip.dst, "TCP", t.sport, t.dport, str(t.flags))
            elif UDP in pkt:
                u = pkt[UDP]
                yield Event(float(pkt.time), ip.src, ip.dst, "UDP", u.sport, u.dport, None)
            else:
                yield Event(float(pkt.time), ip.src, ip.dst, "OTHER", None, None, None)
