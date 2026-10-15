"""
Build samples/attack_traffic.pcap: synthetic lab traffic for testing the rules.

Nothing is sent on the network. Every packet is crafted in memory and written
to a file, using lab and documentation addresses:
    203.0.113.50   "attacker"  (TEST-NET-3, never routed on the internet)
    192.168.56.10  victim server in HOME_NET
    192.168.56.20  workstation in HOME_NET
Benign traffic is mixed in so the tests also prove there are no false alarms.

    python samples/make_sample_pcap.py
"""
import pathlib

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, wrpcap

OUT = pathlib.Path(__file__).with_name("attack_traffic.pcap")
ATTACKER, SERVER, WORKSTATION = "203.0.113.50", "192.168.56.10", "192.168.56.20"
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

packets, clock = [], [1_760_000_000.0]
_sport = [40000]


def add(pkt, gap=0.002):
    clock[0] += gap
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / pkt
    frame.time = clock[0]         # set on the final frame, or scapy uses "now"
    packets.append(frame)


def phase(seconds=3.0):
    """Quiet gap between attack stages, so the timeline shows separate bursts."""
    clock[0] += seconds


def next_port():
    _sport[0] += 1
    return _sport[0]


def tcp_session(cli, srv, dport, exchanges):
    """A complete TCP conversation: handshake, request/response pairs, close."""
    sport = next_port()
    c_seq, s_seq = 1000, 5000
    add(IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c_seq))
    add(IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s_seq, ack=c_seq + 1))
    c_seq += 1; s_seq += 1
    add(IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c_seq, ack=s_seq))
    for client_data, server_data in exchanges:
        if client_data:
            add(IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=c_seq, ack=s_seq) / client_data)
            c_seq += len(client_data)
            add(IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="A", seq=s_seq, ack=c_seq))
        if server_data:
            add(IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=s_seq, ack=c_seq) / server_data)
            s_seq += len(server_data)
            add(IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c_seq, ack=s_seq))
    add(IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=c_seq, ack=s_seq))
    add(IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=s_seq, ack=c_seq + 1))
    add(IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c_seq + 1, ack=s_seq + 1))


def http_get(cli, srv, path, user_agent="Mozilla/5.0", body=b"<html>ok</html>"):
    req = (f"GET {path} HTTP/1.1\r\nHost: {srv}\r\nUser-Agent: {user_agent}\r\n"
           f"Accept: */*\r\n\r\n").encode()
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)
    tcp_session(cli, srv, 80, [(req, resp)])


def build(out=OUT, attacks=True):
    packets.clear()
    clock[0] = 1_760_000_000.0
    # ---- benign baseline: normal browsing, DNS and a few pings (must NOT alert)
    http_get(WORKSTATION, SERVER, "/index.html")
    http_get(WORKSTATION, SERVER, "/products?id=42&sort=price")
    add(IP(src=WORKSTATION, dst="192.168.56.1") / UDP(sport=53001, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="www.example.com")))
    for i in range(3):
        add(IP(src=WORKSTATION, dst=SERVER) / ICMP(type=8, id=1, seq=i), gap=1.0)
    if not attacks:
        wrpcap(str(out), packets)
        return out

    phase()
    # ---- 1000001 ICMP flood
    for i in range(30):
        add(IP(src=ATTACKER, dst=SERVER) / ICMP(type=8, id=7, seq=i), gap=0.05)

    phase()
    # ---- 1000002 SYN port scan (40 ports, server answers RST)
    for port in range(20, 60):
        sp = next_port()
        add(IP(src=ATTACKER, dst=SERVER) / TCP(sport=sp, dport=port, flags="S"), gap=0.01)
        add(IP(src=SERVER, dst=ATTACKER) / TCP(sport=port, dport=sp, flags="RA"), gap=0.001)

    phase()
    # ---- 1000003 NULL scan, 1000004 XMAS scan
    add(IP(src=ATTACKER, dst=SERVER) / TCP(sport=next_port(), dport=443, flags=""))
    add(IP(src=ATTACKER, dst=SERVER) / TCP(sport=next_port(), dport=443, flags="FPU"))

    phase()
    # ---- 1000010 SSH and 1000011 RDP connection floods
    for dport in (22, 3389):
        for _ in range(8):
            add(IP(src=ATTACKER, dst=SERVER) / TCP(sport=next_port(), dport=dport, flags="S"), gap=0.5)

    phase()
    # ---- 1000012 FTP login failures, 1000030 cleartext FTP password
    ftp = [(None, b"220 Lab FTP ready\r\n")]
    for guess in ("123456", "password", "admin", "letmein", "qwerty"):
        ftp += [(b"USER admin\r\n", b"331 Password required\r\n"),
                (f"PASS {guess}\r\n".encode(), b"530 Login incorrect.\r\n")]
    tcp_session(ATTACKER, SERVER, 21, ftp)

    phase()
    # ---- web attacks 1000020-1000024
    http_get(ATTACKER, SERVER, "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users")
    http_get(ATTACKER, SERVER, "/login?user=admin'%20or%20'1'='1")
    http_get(ATTACKER, SERVER, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
    http_get(ATTACKER, SERVER, "/download?file=../../../../etc/passwd")
    http_get(ATTACKER, SERVER, "/", user_agent="sqlmap/1.8#stable (https://sqlmap.org)")

    phase()
    # ---- 1000025 "uid=0(root)" in a response (same content as testmynids.org)
    http_get(WORKSTATION, SERVER, "/uid/index.html",
             body=b"uid=0(root) gid=0(root) groups=0(root)\n")

    phase()
    # ---- 1000031 telnet
    add(IP(src=ATTACKER, dst=SERVER) / TCP(sport=next_port(), dport=23, flags="S"))

    phase()
    # ---- 1000040 EICAR test file served over HTTP
    http_get(WORKSTATION, SERVER, "/eicar.com", body=EICAR)

    phase()
    # ---- 1000041 DNS lookup of a risky TLD
    add(IP(src=WORKSTATION, dst="192.168.56.1") / UDP(sport=53002, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="free-prizes-now.xyz")))

    phase()
    # ---- 1000042 workstation beacons to a blocklisted C2 address
    tcp_session(WORKSTATION, "203.0.113.66", 443, [(b"\x16\x03\x01beacon", None)])

    wrpcap(str(out), packets)
    return out


if __name__ == "__main__":
    print(f"wrote {build()} ({len(packets)} packets)")
