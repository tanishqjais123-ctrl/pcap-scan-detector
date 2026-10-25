from collections import Counter, defaultdict
from dataclasses import dataclass


@dataclass
class Alert:
    rule_id: str
    severity: str
    src: str
    dst: str
    distinct_ports: int
    window_start: float
    window_end: float
    sample_ports: list
    reason: str


def detect_syn_scan(events, window=10.0, threshold=15, high=100):
    groups = defaultdict(list)
    for e in events:
        if e.proto == "TCP" and e.flags == "S":
            groups[(e.src, e.dst)].append((e.time, e.dport))

    alerts = []
    for (src, dst), items in groups.items():
        items.sort()
        counts = Counter()
        left = 0
        best = None
        for right in range(len(items)):
            counts[items[right][1]] += 1
            while items[right][0] - items[left][0] > window:
                counts[items[left][1]] -= 1
                if counts[items[left][1]] == 0:
                    del counts[items[left][1]]
                left += 1
            n = len(counts)
            if n >= threshold and (best is None or n > best[0]):
                best = (n, items[left][0], items[right][0], sorted(counts)[:10])
        if best:
            n, start, end, ports = best
            sev = "high" if n >= high else "medium"
            reason = f"{n} distinct ports probed with SYN in {window:g}s: possible port scan"
            alerts.append(Alert("NET-001", sev, src, dst, n, start, end, ports, reason))
    return alerts
