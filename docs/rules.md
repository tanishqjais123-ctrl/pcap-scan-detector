# Rule NET-001: Possible TCP SYN port scan (vertical)

## What it detects
One source IP sending connection attempts to many different ports on one
destination IP in a short time.

## What counts
- Only TCP packets with the SYN flag set and nothing else (flags == "S").
  These are the first packet of a connection attempt.
- Packets are grouped by (source IP, destination IP).

## Trigger
- Window: 10 seconds (sliding).
- Threshold: 15 distinct destination ports inside one window.
- Both values are starting points, to be tuned on lab captures.

## Alert fields
rule_id, severity, src, dst, distinct_ports, window_start, window_end,
sample_ports, reason.

## Severity
- medium: 15 or more distinct ports in the window.
- high: 100 or more distinct ports in the window.

## Why distinct ports, not packet count
A scan touches many different ports. Retransmissions and SYN floods repeat the
same port. Counting distinct ports separates the two.

## Why SYN only
Normal traffic after the handshake carries ACK or data flags, so counting only
SYN packets ignores established connections.

## What it does NOT detect
- Horizontal scans (one port across many hosts)
- UDP scans
- Slow scans spread over minutes or hours
- FIN, NULL and Xmas scans
- SYN floods (many SYNs to the same port)
- Spoofed source addresses

## Known false positives
Vulnerability scanners, load-testing tools, and software that probes many ports
on purpose (for example some network discovery tools).

## Wording
Alerts say "possible port scan". The tool never claims certainty and never
blocks anything.
