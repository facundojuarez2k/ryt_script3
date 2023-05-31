import logging
import random
# Suprimir warnings en stdout
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
from scapy.all import IP, UDP, DNS, TCP, DNSQR


def main():
    ip_packet = IP(dst="8.8.8.8")
    udp_datagram = UDP(dport=53)
    dns_query = DNS(
        rd=1,                                 # Desactivar lookup recursivo
        qr=0,                                 # Mensaje de tipo query
        qd=DNSQR(qname="example.com"),        # Query
    )
    answer = scapy.sr1(ip_packet/udp_datagram/dns_query, verbose=1)

    print(answer[DNS].summary())

def send_tcp_query():
    ip_dst = "8.8.8.8"
    port_dst = 53
    
    received_ack, received_seq = handshake(ip_dst, port_dst)

    ip_packet = IP(dst=ip_dst)
    tcp_segment = TCP(sport=port_dst, dport=port_dst, flags="PA", seq=received_ack, ack=received_seq + 1)
    dns_request = DNS(rd=1, qd=DNSQR(qname = "example.com", qtype="A"))

    answers, _ = scapy.sr(ip_packet / tcp_segment / dns_request, timeout=3, multi=1)

    print(answers[DNS][0])

def handshake(ip_address, port) -> tuple:
    ip_packet = IP(dst=ip_address)
    tcp_segment = TCP(sport=random.randint(49152, 65535), dport=port, flags="S", seq=random.randint(0, 2**32 - 1))
    syn = ip_packet/tcp_segment
    syn_ack = scapy.sr1(syn)
    ack =   ip_packet/TCP(sport=syn_ack.dport, dport=port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
    scapy.send(ack)
    
    return (syn_ack.ack, syn_ack.seq)

if __name__ == '__main__':
    main()
