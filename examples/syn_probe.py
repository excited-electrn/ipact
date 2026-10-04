from scapy.all import IP, TCP, sr1, conf
conf.verb = 0

# Build a SYN by hand: IP header / TCP header
pkt = IP(dst="127.0.0.1") / TCP(sport=40000, dport=9000, flags="S", seq=1000)
pkt.show()                       # pretty-print every field

reply = sr1(pkt, timeout=2)      # send, and wait for one reply
if reply:
    reply.show()                 # expect flags = SA, ack = 1001
