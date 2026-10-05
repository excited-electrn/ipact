#!/usr/bin/env python3
"""
Sends a series of TCP segments to ipact's ping_responder through tun0.
Run ping_responder first (sudo ./ping_responder), then run this (sudo).

Compare what ping_responder prints with the "expect" line shown for each test.
"""
import subprocess
import sys
import time

from scapy.all import IP, TCP, Raw, send, conf

conf.verb = 0

HOST_IP = "10.0.0.1"   # kernel side of tun0
OUR_IP = "10.0.0.2"    # ipact stack
IFACE = "tun0"
SPORT = 40000
DPORT = 9000


def ensure_iface():
    """Make sure tun0 exists, has 10.0.0.1/24 and is up."""
    if subprocess.run(["ip", "link", "show", IFACE], capture_output=True).returncode != 0:
        sys.exit(f"{IFACE} not found. Start ./ping_responder first.")
    subprocess.run(["ip", "addr", "replace", f"{HOST_IP}/24", "dev", IFACE], check=True)
    subprocess.run(["ip", "link", "set", IFACE, "up"], check=True)


def ip():
    return IP(src=HOST_IP, dst=OUR_IP)


SYN_OPTS = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]

# (name, packet, what ping_responder should print)
TESTS = [
    ("plain SYN, no options",
     ip() / TCP(sport=SPORT, dport=DPORT, flags="S", seq=1000, window=64240),
     f"TCP {SPORT} -> {DPORT} seq=1000 ack=0 hdr=20 win=64240 flags=S opts=0 payload=0"),

    ("SYN with options (MSS, SACK, TS, NOP, WScale)",
     ip() / TCP(sport=SPORT + 1, dport=DPORT, flags="S", seq=2000, window=64240, options=SYN_OPTS),
     f"TCP {SPORT + 1} -> {DPORT} seq=2000 ack=0 hdr=40 win=64240 flags=S opts=20 payload=0"),

    ("SYN with odd-length payload (checksum odd-byte path)",
     ip() / TCP(sport=SPORT + 2, dport=DPORT, flags="S", seq=3000) / Raw(b"hello"),
     f"TCP {SPORT + 2} -> {DPORT} seq=3000 ack=0 hdr=20 ... flags=S opts=0 payload=5"),

    ("ACK|PSH with payload",
     ip() / TCP(sport=SPORT + 3, dport=DPORT, flags="PA", seq=4000, ack=5000) / Raw(b"data!!"),
     f"TCP {SPORT + 3} -> {DPORT} seq=4000 ack=5000 hdr=20 ... flags=AP opts=0 payload=6"),

    ("FIN|ACK",
     ip() / TCP(sport=SPORT + 4, dport=DPORT, flags="FA", seq=6000, ack=7000),
     f"TCP {SPORT + 4} -> {DPORT} seq=6000 ack=7000 hdr=20 ... flags=AF opts=0 payload=0"),

    ("RST",
     ip() / TCP(sport=SPORT + 5, dport=DPORT, flags="R", seq=8000),
     f"TCP {SPORT + 5} -> {DPORT} seq=8000 ack=0 hdr=20 ... flags=R opts=0 payload=0"),

    ("SYN with BAD checksum (must be rejected)",
     ip() / TCP(sport=SPORT + 6, dport=DPORT, flags="S", seq=9000, chksum=0xDEAD),
     "TCP: parse failed (20 bytes)"),
]


def main():
    ensure_iface()
    for i, (name, pkt, expect) in enumerate(TESTS, 1):
        print(f"[{i}/{len(TESTS)}] {name}")
        print(f"    expect: {expect}")
        send(pkt, iface=IFACE)
        time.sleep(0.2)  # keep output in order
    print("done")


if __name__ == "__main__":
    main()
