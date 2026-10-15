"""Thin wrapper around the Suricata binary: build the command line and run it."""
import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "rules" / "local.rules"
THRESHOLD = ROOT / "config" / "threshold.config"
LOG_DIR = ROOT / "logs"


def suricata_exe():
    found = os.environ.get("SURICATA_EXE") or shutil.which("suricata")
    if found:
        return pathlib.Path(found)
    default = pathlib.Path(r"C:\Program Files\Suricata\suricata.exe")
    if default.exists():
        return default
    raise FileNotFoundError("Suricata not found. Install it or set SURICATA_EXE.")


def command(source_args, log_dir=LOG_DIR, home_net=None):
    exe = suricata_exe()
    cmd = [str(exe), "-c", str(exe.parent / "suricata.yaml"),
           "-S", str(RULES),                      # load ONLY our rule file
           "-l", str(log_dir),
           "--set", f"threshold-file={THRESHOLD}",
           "-k", "none"]                          # ignore bad checksums (NIC offload)
    if home_net:
        cmd += ["--set", f"vars.address-groups.HOME_NET={home_net}"]
    return cmd + source_args


def run_offline(pcap, log_dir=LOG_DIR, home_net=None):
    """Analyse a capture file and return the path to eve.json."""
    log_dir = pathlib.Path(log_dir).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    for old in ("eve.json", "fast.log"):
        (log_dir / old).unlink(missing_ok=True)
    exe = suricata_exe()
    pcap = pathlib.Path(pcap).resolve()
    args = ["--runmode", "single", "-r", str(pcap)]   # single thread keeps alerts in order
    result = subprocess.run(command(args, log_dir, home_net), cwd=exe.parent,
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError("Suricata failed:\n" + result.stdout[-2000:] + result.stderr[-2000:])
    return log_dir / "eve.json"


def start_live(interface, log_dir=LOG_DIR, home_net=None):
    """Start continuous live capture on an Npcap device; returns the Popen."""
    log_dir = pathlib.Path(log_dir).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    exe = suricata_exe()
    return subprocess.Popen(command(["-i", interface], log_dir, home_net), cwd=exe.parent,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
