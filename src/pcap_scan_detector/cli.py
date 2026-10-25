import argparse
import json
import sys
from dataclasses import asdict

from .parser import read_events
from .detector import detect_syn_scan


def build_parser():
    p = argparse.ArgumentParser(
        prog="pcap-scan",
        description="Flag possible TCP SYN port scans in a PCAP file.",
    )
    p.add_argument("pcap", help="path to a .pcap or .pcapng file")
    p.add_argument("--window", type=float, default=10.0, help="window in seconds (default 10)")
    p.add_argument("--threshold", type=int, default=15, help="distinct ports to trigger (default 15)")
    p.add_argument("--json", dest="json_path", help="also write the report to this JSON file")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.window <= 0 or args.threshold < 1:
        parser.error("--window must be above 0 and --threshold at least 1")

    try:
        alerts = detect_syn_scan(read_events(args.pcap), window=args.window, threshold=args.threshold)
    except FileNotFoundError:
        print(f"error: file not found: {args.pcap}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: could not read {args.pcap}: {exc}", file=sys.stderr)
        return 2

    if not alerts:
        print("No possible port scans found.")
    for a in alerts:
        print(f"[{a.severity.upper()}] {a.rule_id} {a.src} -> {a.dst}: {a.reason}")
        print(f"    sample ports: {a.sample_ports}")

    if args.json_path:
        report = {
            "file": args.pcap,
            "window": args.window,
            "threshold": args.threshold,
            "alert_count": len(alerts),
            "alerts": [asdict(a) for a in alerts],
        }
        with open(args.json_path, "w") as f:
            json.dump(report, f, indent=2)

    return 1 if alerts else 0
