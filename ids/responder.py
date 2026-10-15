"""
Response engine: decides what to do with each Suricata alert.

Actions, by alert priority (1 = high):
  every alert           -> written to logs/incidents.jsonl (for the dashboard)
  priority 1 or 2       -> desktop notification (rate-limited per signature)
  priority 1, or 3+ priority-1/2 alerts from one external IP in 2 minutes
                        -> block that IP with a Windows Firewall rule
  priority 3            -> logged only (e.g. a risky DNS lookup must not
                           get the DNS resolver itself blocked)

Safety:
  * Only EXTERNAL addresses are ever blocked. Internal hosts (RFC 1918,
    loopback, link-local) and anything in the allow-list just raise alerts.
  * Blocking is DRY-RUN by default: the decision is logged as "would_block".
    Pass enforce=True (needs an Administrator shell) to create real rules.
  * Every rule this tool creates is named "SentinelIDS-block-<ip>", so
    unblock_all() removes exactly those and nothing else.
"""
import ipaddress
import json
import pathlib
import subprocess
import time
from collections import defaultdict, deque

RULE_PREFIX = "SentinelIDS-block-"
NOTIFY_COOLDOWN = 30          # seconds between popups for the same signature
REPEAT_WINDOW, REPEAT_COUNT = 120, 3


INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",      # RFC 1918 LAN ranges
    "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",       # loopback, link-local, multicast
    "255.255.255.255/32", "0.0.0.0/32",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True           # unparseable: never block
    return any(addr in net for net in INTERNAL_NETS if net.version == addr.version)


def endpoint(ip, port):
    """'1.2.3.4:80', '[::1]:80', or just the IP for port-less protocols (ICMP)."""
    if port in (None, ""):
        return ip
    return f"[{ip}]:{port}" if ip and ":" in ip else f"{ip}:{port}"


def offender_of(alert):
    """The external side of the flow, or None if both ends are internal."""
    for ip in (alert.get("src_ip"), alert.get("dest_ip")):
        if ip and not is_internal(ip):
            return ip
    return None


class Responder:
    def __init__(self, incidents_path, enforce=False, notify=True, allowlist=()):
        self.incidents_path = pathlib.Path(incidents_path)
        self.incidents_path.parent.mkdir(parents=True, exist_ok=True)
        self.enforce = enforce
        self.notify = notify
        self.allowlist = set(allowlist)
        self.blocked = set()
        self._recent = defaultdict(deque)       # ip -> alert timestamps
        self._last_popup = {}

    # ------------------------------------------------------------ decisions
    def handle(self, event):
        """Process one eve.json alert event; returns the incident record."""
        a = event["alert"]
        priority = a.get("severity", 3)
        offender = offender_of(event)
        actions = ["logged"]

        if priority <= 2 and self._may_popup(a["signature_id"]):
            actions.append("notified")
            if self.notify:
                self._popup(a["signature"], event)

        # priority 3 is informational: alert only, never counts toward a block
        if offender and priority <= 2 and offender not in self.allowlist:
            now = time.time()
            hits = self._recent[offender]
            hits.append(now)
            while hits and now - hits[0] > REPEAT_WINDOW:
                hits.popleft()
            if (priority == 1 or len(hits) >= REPEAT_COUNT) and offender not in self.blocked:
                actions.append(self.block(offender))

        record = {
            "time": event.get("timestamp"),
            "sid": a["signature_id"],
            "signature": a["signature"],
            "category": a.get("category"),
            "priority": priority,
            "proto": event.get("proto"),
            "src_ip": event.get("src_ip"),
            "src": endpoint(event.get("src_ip"), event.get("src_port")),
            "dst": endpoint(event.get("dest_ip"), event.get("dest_port")),
            "offender": offender,
            "actions": actions,
        }
        with self.incidents_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
        return record

    def _may_popup(self, sid):
        now = time.time()
        if now - self._last_popup.get(sid, 0) < NOTIFY_COOLDOWN:
            return False
        self._last_popup[sid] = now
        return True

    # ------------------------------------------------------------ actions
    def block(self, ip):
        self.blocked.add(ip)
        if not self.enforce:
            return "would_block"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={RULE_PREFIX}{ip}", "dir=in", "action=block", f"remoteip={ip}"]
        ok = subprocess.run(cmd, capture_output=True).returncode == 0
        return "blocked" if ok else "block_failed"

    @staticmethod
    def _popup(title, event):
        """Non-blocking Windows tray notification."""
        msg = f'{event.get("src_ip")} -> {event.get("dest_ip")}:{event.get("dest_port", "")}'
        ps = ("Add-Type -AssemblyName System.Windows.Forms;"
              "$n=New-Object System.Windows.Forms.NotifyIcon;"
              "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
              f"$n.ShowBalloonTip(6000,'SentinelIDS alert',{json.dumps(title + ' | ' + msg)},'Warning');"
              "Start-Sleep 7;$n.Dispose()")
        try:
            subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


def unblock_all():
    """Remove every firewall rule created by SentinelIDS (needs Administrator)."""
    out = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                         capture_output=True, text=True).stdout
    names = {line.split(":", 1)[1].strip() for line in out.splitlines()
             if line.startswith("Rule Name:") and RULE_PREFIX in line}
    for name in names:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                       capture_output=True)
    return sorted(names)
