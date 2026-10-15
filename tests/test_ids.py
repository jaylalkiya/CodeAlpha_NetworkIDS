"""
SentinelIDS test suite.

  * every custom rule fires on the synthetic attack capture
  * normal traffic raises no alerts (no false positives)
  * the response engine only ever blocks external addresses
  * the dashboard API summarises incidents correctly

Run from the NetworkIDS folder:   python -m pytest -v
Requires Suricata (C:\\Program Files\\Suricata or SURICATA_EXE).
"""
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ids"))
sys.path.insert(0, str(ROOT / "samples"))
sys.path.insert(0, str(ROOT / "dashboard"))

import engine                                                   # noqa: E402
import make_sample_pcap                                         # noqa: E402
from responder import Responder, is_internal, offender_of       # noqa: E402

ALL_SIDS = sorted(int(m) for m in re.findall(r"sid:(\d+);", (ROOT / "rules" / "local.rules").read_text()))


def alerts_from(eve):
    out = []
    with open(eve, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            if e.get("event_type") == "alert":
                out.append(e)
    return out


@pytest.fixture(scope="module")
def attack_alerts(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("attack")
    pcap = make_sample_pcap.build(tmp / "attack.pcap")
    return alerts_from(engine.run_offline(pcap, tmp / "logs"))


@pytest.fixture(scope="module")
def benign_alerts(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("benign")
    pcap = make_sample_pcap.build(tmp / "benign.pcap", attacks=False)
    return alerts_from(engine.run_offline(pcap, tmp / "logs"))


# ------------------------------------------------------------------ detection
def test_ruleset_has_18_rules():
    assert len(ALL_SIDS) == 18 and len(set(ALL_SIDS)) == 18


@pytest.mark.parametrize("sid", ALL_SIDS)
def test_rule_fires(attack_alerts, sid):
    assert sid in {a["alert"]["signature_id"] for a in attack_alerts}


def test_no_false_positives_on_normal_traffic(benign_alerts):
    assert benign_alerts == []


def test_thresholds_need_volume(benign_alerts):
    """3 normal pings must not trip the 20-per-10s ICMP flood rule."""
    assert not any(a["alert"]["signature_id"] == 1000001 for a in benign_alerts)


# ------------------------------------------------------------------ response
def fake_alert(src, dst, severity=2, sid=1000002):
    return {"timestamp": "2026-10-15T12:00:00.000000+0530", "proto": "TCP",
            "src_ip": src, "src_port": 4444, "dest_ip": dst, "dest_port": 80,
            "alert": {"signature_id": sid, "signature": "SENTINEL TEST alert",
                      "category": "test", "severity": severity}}


@pytest.mark.parametrize("ip", ["10.1.2.3", "172.20.0.5", "192.168.1.10", "127.0.0.1",
                                "169.254.9.9", "::1", "fe80::1", "not-an-ip"])
def test_internal_addresses(ip):
    assert is_internal(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "203.0.113.50", "2606:4700::1111"])
def test_external_addresses(ip):
    assert not is_internal(ip)


def test_offender_is_external_side():
    assert offender_of(fake_alert("192.168.56.10", "203.0.113.50")) == "203.0.113.50"
    assert offender_of(fake_alert("203.0.113.50", "192.168.56.10")) == "203.0.113.50"
    assert offender_of(fake_alert("192.168.56.20", "192.168.56.1")) is None


def test_high_priority_external_is_blocked_dry_run(tmp_path):
    r = Responder(tmp_path / "inc.jsonl", notify=False)
    rec = r.handle(fake_alert("203.0.113.50", "192.168.56.10", severity=1))
    assert "would_block" in rec["actions"] and "203.0.113.50" in r.blocked


def test_internal_host_is_never_blocked(tmp_path):
    r = Responder(tmp_path / "inc.jsonl", notify=False)
    for _ in range(10):
        rec = r.handle(fake_alert("192.168.56.20", "192.168.56.1", severity=1))
    assert r.blocked == set() and "would_block" not in rec["actions"]


def test_repeat_offender_blocked_after_three_alerts(tmp_path):
    r = Responder(tmp_path / "inc.jsonl", notify=False)
    acts = [r.handle(fake_alert("198.51.100.7", "192.168.56.10", severity=2))["actions"]
            for _ in range(3)]
    assert "would_block" not in acts[0] and "would_block" not in acts[1]
    assert "would_block" in acts[2]


def test_low_priority_never_blocks(tmp_path):
    """A risky DNS lookup must not get the resolver (e.g. 8.8.8.8) blocked."""
    r = Responder(tmp_path / "inc.jsonl", notify=False)
    for _ in range(10):
        r.handle(fake_alert("192.168.56.20", "8.8.8.8", severity=3, sid=1000041))
    assert r.blocked == set()


def test_allowlist_is_respected(tmp_path):
    r = Responder(tmp_path / "inc.jsonl", notify=False, allowlist=["203.0.113.50"])
    r.handle(fake_alert("203.0.113.50", "192.168.56.10", severity=1))
    assert r.blocked == set()


def test_blocked_once_only(tmp_path):
    r = Responder(tmp_path / "inc.jsonl", notify=False)
    recs = [r.handle(fake_alert("203.0.113.50", "192.168.56.10", severity=1)) for _ in range(5)]
    assert sum("would_block" in x["actions"] for x in recs) == 1


def test_incidents_are_logged(tmp_path):
    r = Responder(tmp_path / "inc.jsonl", notify=False)
    r.handle(fake_alert("203.0.113.50", "192.168.56.10"))
    row = json.loads((tmp_path / "inc.jsonl").read_text().splitlines()[0])
    assert row["src"] == "203.0.113.50:4444" and row["sid"] == 1000002


# ------------------------------------------------------------------ dashboard
def test_dashboard_summary(tmp_path, attack_alerts, monkeypatch):
    import app as dashboard
    inc = tmp_path / "incidents.jsonl"
    r = Responder(inc, notify=False)
    for a in attack_alerts:
        r.handle(a)
    monkeypatch.setattr(dashboard, "INCIDENTS", inc)
    data = dashboard.app.test_client().get("/api/summary").get_json()
    assert data["total"] == len(attack_alerts)
    assert data["rules_fired"] == 18
    assert {b["ip"] for b in data["blocked"]} == {"203.0.113.50", "203.0.113.66"}
    assert {c for c, _ in data["by_category"]} == {"RECON", "BRUTEFORCE", "WEB", "POLICY", "MALWARE"}
