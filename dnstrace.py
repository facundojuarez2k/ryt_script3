import logging
# Suprimir warnings en stdout
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
from scapy.all import IP, UDP, DNS, DNSQR


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


if __name__ == '__main__':
    main()
