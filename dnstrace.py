import random
import logging
# Suprimir warnings en stdout
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, UDP, DNS, DNSQR
import scapy.all as scapy
# Importar diccionario de DNS record types y classes
from scapy.layers.dns import dnstypes, dnsclasses

DEFAULT_RESOLVER = "8.8.8.8"

def main():
    resolver_address: str = get_main_resolver() or DEFAULT_RESOLVER
    resolve_dns("b.dns.ar", DEFAULT_RESOLVER)

def resolve_dns(fqdn: str, resolver_address: str):
    '''
    Retorna una lista de registros A para un FQDN utilizando el solucionador provisto
    '''
    
    fqdn += "."
    ip_packet = IP(dst=resolver_address)
    udp_segment = UDP(dport=53)
    dns_query = DNS(rd=1, qd=DNSQR(qname=fqdn))
    addresses = []

    dns_answer = scapy.sr1(ip_packet/udp_segment/dns_query, verbose=0, timeout=0)

    if dns_answer is None:
        print("Timeout")
        return addresses

    for index in range(dns_answer[DNS].ancount):
        record_name = dns_answer[DNS].an[index].rrname.decode("utf-8")
        record_class = dnsclasses[dns_answer[DNS].an[index].rclass]
        record_type = dnstypes[dns_answer[DNS].an[index].type]
        record_data = dns_answer[DNS].an[index].rdata

        if record_type != "A":
            continue

        addresses.append(record_data)

        #print(f'{record_name}   {record_class}  {record_type}   {record_data}')

    return addresses

def get_main_resolver():
    """
    Retorna el primer nameserver del archivo /etc/resolv.conf
    :returns: Dirección IP del nameserver o None en caso de que no exista un valor
    """
    resolver_list = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as config_file:
            for line in config_file.readlines():
                line = line.lstrip()
                
                if line.startswith("#"):
                    continue
        
                if "nameserver" in line:
                    resolver_list.append(line.split()[1])   # Extraer la dirección IP
        
        return resolver_list[0] if len(resolver_list) > 0 else None
    except Exception:
        return None

if __name__ == "__main__":
    main()
