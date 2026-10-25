import json

from scapy.all import Ether, IP, TCP, wrpcap
from pcap_scan_detector.cli import main


def make_scan(path, n=20):
    pkts = []
    for i in range(n):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=1000 + i, flags="S")
        p.time = 1000.0 + i * 0.1
        pkts.append(p)
    wrpcap(str(path), pkts)


def test_scan_found(tmp_path, capsys):
    p = tmp_path / "scan.pcap"
    make_scan(p)
    assert main([str(p)]) == 1
    assert "NET-001" in capsys.readouterr().out


def test_json_report(tmp_path):
    p = tmp_path / "scan.pcap"
    out = tmp_path / "report.json"
    make_scan(p)
    main([str(p), "--json", str(out)])
    data = json.loads(out.read_text())
    assert data["alert_count"] == 1
    assert data["alerts"][0]["src"] == "10.0.0.1"


def test_clean_file(tmp_path, capsys):
    p = tmp_path / "empty.pcap"
    wrpcap(str(p), [])
    assert main([str(p)]) == 0
    assert "No possible port scans" in capsys.readouterr().out


def test_missing_file(tmp_path, capsys):
    assert main([str(tmp_path / "nope.pcap")]) == 2
    assert "not found" in capsys.readouterr().err


def test_not_a_capture(tmp_path, capsys):
    p = tmp_path / "text.pcap"
    p.write_text("this is not a pcap")
    assert main([str(p)]) == 2
    assert "error" in capsys.readouterr().err
