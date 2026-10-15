"""
SentinelIDS - command-line entry point.

  python ids/sentinel.py interfaces                 list capture devices
  python ids/sentinel.py live [--iface DEV]         monitor continuously
  python ids/sentinel.py replay samples/attack_traffic.pcap [--realtime]
  python ids/sentinel.py unblock                    remove all block rules

Options for live/replay:
  --enforce     really add Windows Firewall block rules (Administrator shell)
  --no-popup    no desktop notifications
  --allow IP    never block this IP (repeatable)
"""
import argparse
import ctypes
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import engine                                    # noqa: E402
from responder import Responder, unblock_all     # noqa: E402

G, R, Y, D, B, X = "\033[92m", "\033[91m", "\033[93m", "\033[2m", "\033[1m", "\033[0m"
INCIDENTS = engine.LOG_DIR / "incidents.jsonl"
BANNER = rf"""{G}{B}
   ____             _   _            _ ___ ____  ____
  / ___|  ___ _ __ | |_(_)_ __   ___| |_ _|  _ \/ ___|
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ | | || | | \___ \
   ___) |  __/ | | | |_| | | | |  __/ | | || |_| |___) |
  |____/ \___|_| |_|\__|_|_| |_|\___|_||___|____/|____/
{X}{D}  Suricata-powered network intrusion detection  //  CodeAlpha Task 4{X}
"""


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except AttributeError:
        return False


def show(rec):
    colour = {1: R, 2: Y}.get(rec["priority"], D)
    acts = ",".join(a for a in rec["actions"] if a != "logged")
    print(f'{D}{(rec["time"] or "")[11:19]}{X} {colour}[P{rec["priority"]}]{X} '
          f'{rec["signature"]:<58.58} {rec["src"]:>21} -> {rec["dst"]:<21} '
          f'{G}{acts}{X}', flush=True)


def follow(path, stop):
    """Yield new lines appended to a file (tail -f), until stop() is true."""
    while not path.exists():
        if stop():
            return
        time.sleep(0.5)
    with path.open(encoding="utf-8") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line
            elif stop():
                return
            else:
                time.sleep(0.3)


def handle_lines(lines, responder, stats):
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            stats["alerts"] += 1
            show(responder.handle(event))


def paced(lines, speed):
    """Re-play events with their original spacing (gaps capped at 3 s)."""
    from datetime import datetime
    last = None
    for line in lines:
        try:
            ts = datetime.fromisoformat(json.loads(line)["timestamp"]).timestamp()
        except (ValueError, KeyError):
            yield line
            continue
        if last is not None and ts > last:
            time.sleep(min(ts - last, 3.0) / speed)
        last = ts
        yield line


def default_iface():
    from scapy.all import conf
    return conf.iface.network_name


def cmd_interfaces(_args):
    from scapy.all import conf
    for iface in conf.ifaces.values():
        print(f"{iface.network_name:<60} {iface.ip or '-':<16} {iface.description}")


def make_responder(args):
    if args.enforce and not is_admin():
        sys.exit(f"{R}--enforce needs an Administrator shell.{X}")
    INCIDENTS.parent.mkdir(exist_ok=True)
    INCIDENTS.write_text("")
    mode = f"{R}ENFORCE (firewall rules){X}" if args.enforce else f"{Y}DRY-RUN (logs 'would_block'){X}"
    print(f"  response mode: {mode}\n")
    return Responder(INCIDENTS, enforce=args.enforce, notify=not args.no_popup,
                     allowlist=args.allow or [])


def cmd_replay(args):
    print(BANNER)
    responder = make_responder(args)
    print(f"  replaying {args.pcap} through Suricata ...\n")
    eve = engine.run_offline(args.pcap)
    stats = {"alerts": 0}
    with eve.open(encoding="utf-8") as f:
        lines = f.readlines()
    if args.realtime:
        lines = paced(lines, args.speed)
    handle_lines(lines, responder, stats)
    print(f"\n{G}{B}  {stats['alerts']} alerts, {len(responder.blocked)} offender(s): "
          f"{', '.join(sorted(responder.blocked)) or '-'}{X}")


def cmd_live(args):
    print(BANNER)
    iface = args.iface or default_iface()
    responder = make_responder(args)
    eve = engine.LOG_DIR / "eve.json"
    eve.unlink(missing_ok=True)
    proc = engine.start_live(iface, home_net=args.home_net)
    print(f"  monitoring {iface}  (Ctrl+C to stop)\n")
    stats = {"alerts": 0}
    try:
        handle_lines(follow(eve, lambda: proc.poll() is not None), responder, stats)
        print(f"{R}Suricata exited (code {proc.returncode}). See logs/suricata.log{X}")
    except KeyboardInterrupt:
        pass
    finally:
        if proc.poll() is None:
            proc.terminate()
        print(f"\n{G}  stopped. {stats['alerts']} alerts this session.{X}")


def cmd_unblock(_args):
    if not is_admin():
        sys.exit(f"{R}unblock needs an Administrator shell.{X}")
    removed = unblock_all()
    print(f"removed {len(removed)} rule(s): {', '.join(removed) or '-'}")


def main():
    p = argparse.ArgumentParser(description="SentinelIDS")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("interfaces").set_defaults(fn=cmd_interfaces)
    for name, fn in (("live", cmd_live), ("replay", cmd_replay)):
        s = sub.add_parser(name)
        if name == "replay":
            s.add_argument("pcap")
            s.add_argument("--realtime", action="store_true",
                           help="feed alerts at their original pace (for demos)")
            s.add_argument("--speed", type=float, default=1.0)
        else:
            s.add_argument("--iface")
            s.add_argument("--home-net", help='e.g. "[192.168.1.0/24]"')
        s.add_argument("--enforce", action="store_true")
        s.add_argument("--no-popup", action="store_true")
        s.add_argument("--allow", action="append")
        s.set_defaults(fn=fn)
    sub.add_parser("unblock").set_defaults(fn=cmd_unblock)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
