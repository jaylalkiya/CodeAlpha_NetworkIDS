# CodeAlpha_NetworkIDS: SentinelIDS

**CodeAlpha Cyber Security Internship, Task 4: Network Intrusion Detection System**

SentinelIDS is a network-based intrusion detection system built on
**Suricata 7**. It adds 18 custom detection rules, an automatic response
engine (notifications and firewall blocking) and a live hacker-style
dashboard.

```
          ┌────────────┐   packets   ┌──────────────┐  eve.json  ┌────────────────┐ incidents ┌─────────────┐
 Network ─┤ Npcap / pcap├───────────►│  Suricata 7  ├───────────►│  Response      ├──────────►│  Dashboard  │
 (Wi-Fi)  └────────────┘             │ 18 custom    │  alerts    │  engine        │  .jsonl   │  Flask +    │
                                     │ rules        │            │ log · notify · │           │  Chart.js   │
                                     └──────────────┘            │ firewall block │           └─────────────┘
                                                                 └────────────────┘
```

## What it covers (task checklist)

| Requirement | How SentinelIDS does it |
|---|---|
| Set up a network IDS with Snort or Suricata | Suricata 7.0.10 on Windows, live capture through Npcap |
| Configure rules and alerts | `rules/local.rules`: 18 custom rules in 5 categories, with thresholds and priorities |
| Monitor traffic continuously | `sentinel.py live` runs Suricata on the network adapter and follows alerts in real time |
| Response mechanisms | Incident log, desktop notification, and automatic Windows Firewall block of the external attacker |
| Visualise attacks (optional) | Live dashboard: KPIs, timeline, categories, top signatures, blocked offenders, alert feed |

## Detection rules

| SID | Category | Detects | Priority |
|---|---|---|---|
| 1000001 | Recon | ICMP ping flood / sweep (20+ in 10 s) | 2 |
| 1000002 | Recon | TCP SYN port scan (25+ SYNs in 5 s) | 2 |
| 1000003 | Recon | TCP NULL scan | 2 |
| 1000004 | Recon | TCP XMAS scan | 2 |
| 1000010 | Brute force | Repeated SSH connection attempts | 1 |
| 1000011 | Brute force | Repeated RDP connection attempts | 1 |
| 1000012 | Brute force | Repeated FTP login failures (`530`) | 1 |
| 1000020 | Web | SQL injection, `UNION SELECT` | 1 |
| 1000021 | Web | SQL injection, `' or 1=1` tautology | 1 |
| 1000022 | Web | Cross-site scripting `<script>` | 1 |
| 1000023 | Web | Directory traversal `../` | 1 |
| 1000024 | Web | Scanner user-agents (sqlmap, nikto, nmap ...) | 2 |
| 1000025 | Web | `uid=0(root)` in a response (testmynids.org check) | 1 |
| 1000030 | Policy | Cleartext FTP password | 2 |
| 1000031 | Policy | Telnet connection attempt | 2 |
| 1000040 | Malware | EICAR antivirus test string | 1 |
| 1000041 | Malware | DNS lookup of a high-risk TLD (.xyz, .top, .tk ...) | 3 |
| 1000042 | Malware | Traffic to a blocklisted C2 address | 1 |

## Response engine

| Trigger | Action |
|---|---|
| Every alert | Written to `logs/incidents.jsonl` (feeds the dashboard) |
| Priority 1–2 | Desktop notification, rate-limited per rule |
| Priority 1, or 3 priority 1–2 alerts from one IP within 2 min | Block the offender with a Windows Firewall rule |
| Priority 3 | Logged only |

Safety rules:
- **Only external addresses are blocked.** Your own LAN hosts, router,
  loopback and link-local addresses only ever raise alerts.
- **Dry-run by default.** Decisions are logged as `would_block`. Add
  `--enforce` from an Administrator terminal to create real firewall rules.
- An allow-list (`--allow IP`) protects addresses that must never be blocked.
- Every firewall rule is named `SentinelIDS-block-<ip>`, and
  `sentinel.py unblock` removes exactly those rules.

## Quick start (Windows)

1. Install [Npcap](https://npcap.com) and Suricata:
   `winget install OISF.Suricata`
2. `pip install -r requirements.txt`

```bash
# list capture devices
python ids/sentinel.py interfaces

# replay the bundled sample capture (no network access needed)
python ids/sentinel.py replay samples/attack_traffic.pcap

# live monitoring of your network adapter (Ctrl+C to stop)
python ids/sentinel.py live
python ids/sentinel.py live --enforce          # Administrator: real firewall blocks

# dashboard: run in a second terminal, then open http://127.0.0.1:8050
python dashboard/app.py

# tests: 41 checks
python -m pytest -v
```

Safe ways to see live alerts on your own machine:
```bash
nslookup free-prizes-now.xyz          # 1000041 risky TLD (P3, alert only)
curl -m 3 http://203.0.113.66/        # 1000042 C2 blocklist (reserved, unroutable address)
```

## Testing

`samples/make_sample_pcap.py` builds a **synthetic** capture in memory (no
packets are sent). It uses documentation and lab addresses, and mixes normal
browsing, DNS and pings with one example of each detectable technique. The
test suite (`tests/test_ids.py`, **41 passed**) checks that:
- each of the 18 rules fires on the attack capture
- normal traffic produces **zero** alerts (no false positives)
- internal hosts are never blocked, low-priority alerts never block,
  offenders are blocked only once, and the allow-list works
- the dashboard API summarises incidents correctly

Live monitoring was also verified on a real Wi-Fi adapter: the C2,
ping-flood and risky-DNS rules fired with the correct response for each.

## Project structure

```
rules/local.rules          18 custom Suricata rules
config/threshold.config    threshold/suppression overrides (empty by default)
ids/engine.py              builds the Suricata command line (live / offline)
ids/responder.py           response engine: log, notify, firewall block
ids/sentinel.py            CLI: interfaces | live | replay | unblock
dashboard/                 Flask + Chart.js live dashboard
samples/                   synthetic test capture and its generator
tests/test_ids.py          detection, response and dashboard tests
docs/                      setup notes and test results
```

## Tools

Suricata 7.0.10 · Npcap · Python 3.12 · Scapy · Flask · Chart.js · pytest
