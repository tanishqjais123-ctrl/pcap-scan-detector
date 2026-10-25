from pcap_scan_detector.parser import Event
from pcap_scan_detector.detector import detect_syn_scan


def syn(t, port, src="10.0.0.1", dst="10.0.0.2"):
    return Event(t, src, dst, "TCP", 40000, port, "S")


def test_below_threshold_no_alert():
    events = [syn(i * 0.1, 1000 + i) for i in range(14)]
    assert detect_syn_scan(events) == []


def test_at_threshold_alert():
    events = [syn(i * 0.1, 1000 + i) for i in range(15)]
    alerts = detect_syn_scan(events)
    assert len(alerts) == 1
    assert alerts[0].distinct_ports == 15
    assert alerts[0].severity == "medium"


def test_high_severity():
    events = [syn(i * 0.05, 1000 + i) for i in range(100)]
    alerts = detect_syn_scan(events)
    assert len(alerts) == 1
    assert alerts[0].severity == "high"


def test_same_port_repeated_no_alert():
    events = [syn(i * 0.1, 443) for i in range(50)]
    assert detect_syn_scan(events) == []


def test_slow_scan_outside_window():
    events = [syn(i * 11, 1000 + i) for i in range(20)]
    assert detect_syn_scan(events) == []


def test_ignores_non_syn():
    events = [Event(i * 0.1, "10.0.0.1", "10.0.0.2", "TCP", 40000, 1000 + i, "SA") for i in range(30)]
    assert detect_syn_scan(events) == []


def test_empty_input():
    assert detect_syn_scan([]) == []


def test_different_targets_not_mixed():
    a = [syn(i * 0.1, 1000 + i, dst="10.0.0.2") for i in range(10)]
    b = [syn(i * 0.1, 2000 + i, dst="10.0.0.3") for i in range(10)]
    assert detect_syn_scan(a + b) == []
