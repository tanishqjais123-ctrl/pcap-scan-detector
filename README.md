# pcap-scan-detector

A small Python tool that reads a PCAP capture file and flags **possible TCP SYN port scans**.

> Status: v0.1.0, a learning project. It detects one pattern well and says so. It is not a replacement for Zeek, Suricata or Snort.

## What it does

A port scan probes many ports on a machine to find which are open. This tool reads a capture offline, counts the distinct ports one source tries on one target within a short time window, and raises an alert when the count passes a threshold. It never blocks anything, and alerts say "possible" because a scan can look like legitimate activity.

## How the rule works (NET-001)

- Only TCP packets with just the SYN flag set are counted (the first packet of a connection attempt).
- Packets are grouped by (source IP, destination IP).
- Default trigger: 15 or more **distinct destination ports** inside a 10-second sliding window.
- Severity is `medium` from 15 ports and `high` from 100 ports.

Counting distinct ports, not packets, is what separates a scan from a busy client: 30 web requests are 30 SYNs but only one port. Full details are in [docs/rules.md](docs/rules.md).

## Install

Requires Python 3.10 or newer (developed on Python 3.14, Kali Linux).

```bash
git clone https://github.com/tanishqjais123-ctrl/pcap-scan-detector.git
cd pcap-scan-detector
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Usage

```bash
pcap-scan capture.pcap
pcap-scan capture.pcap --window 60 --threshold 15
pcap-scan capture.pcap --json report.json
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--window` | 10 | Window length in seconds |
| `--threshold` | 15 | Distinct ports needed to raise an alert |
| `--json FILE` | off | Also write the report to a JSON file |

Exit codes: `0` nothing found, `1` possible scan found, `2` error (missing or unreadable file).

## Example output

```text
[HIGH] NET-001 127.0.0.1 -> 127.0.0.1: 1000 distinct ports probed with SYN in 10s: possible port scan
    sample ports: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
```

## Lab results

Tested in an isolated Kali VM, scanning only the VM itself (`127.0.0.1`).

| Capture | What it was | Result |
| --- | --- | --- |
| Baseline | 66 packets of normal traffic (DNS, HTTPS, ping) | No alert |
| Benign burst | 975 packets, 30 web requests (30 SYNs, all to port 443) | No alert |
| Fast scan | `nmap -sS -p 1-1000` | HIGH alert, 1000 distinct ports |
| Slow scan | `nmap -sS -p 1-25 --scan-delay 2s` | Missed at the default window. Caught as MEDIUM with `--window 60` |

This is a small lab sample, not a measured detection rate.

## Limitations

- Detects only vertical TCP SYN scans (many ports on one host).
- Does not detect horizontal scans, UDP scans, FIN/NULL/Xmas scans, SYN floods or spoofed sources.
- Slow scans can slip under the default 10-second window. A longer window catches them but raises the false-positive risk on busy hosts.
- Thresholds are starting values tuned on a few lab captures only.
- Vulnerability scanners and network discovery tools will trigger it by design.
- Timestamps in alerts are raw epoch seconds.

## Ethics and safe use

Only analyze captures you are allowed to analyze, and only scan systems you own or have written permission to test. The lab results above come from scanning the author's own virtual machine.

## Project layout

```text
src/pcap_scan_detector/   parser.py, detector.py, cli.py
tests/                    pytest suite (16 tests)
docs/rules.md             rule specification
```

Run the tests with `pytest -q`.

## License

MIT, see [LICENSE](LICENSE).
