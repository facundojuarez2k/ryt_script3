import random
import logging
# Suprimir warnings en stdout
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, UDP, DNS, DNSQR
import scapy.all as scapy
# Importar diccionario de DNS record types y classes
from scapy.layers.dns import dnstypes, dnsclasses

DEFAULT_DNS = "8.8.8.8"

def main():
    resolver_address: str = get_main_nameserver() or DEFAULT_DNS
    trace("uns.edu.ar", DEFAULT_DNS)

def resolve_dns(query: str, dns_address: str, record_type: str, recursive_lookup: bool = False, record_class: str = "IN"):
    '''
    Retorna la respuesta de Scapy para una consulta directa a un servidor DNS
    :param: query String con la string a consultar
    :param: dns_address Dirección IP del servidor DNS a consultar
    :param: record_type Tipo de registro DNS
    :param: recursive_lookup Determina si la busqueda debe hacerse recursivamente
    '''
    
    ip_packet = IP(dst=dns_address)
    udp_segment = UDP(dport=53)
    dns_query = DNS(
        rd=recursive_lookup, 
        qd=DNSQR(qname=query, qtype=record_type, qclass=record_class),
    )

    answer = scapy.sr1(ip_packet/udp_segment/dns_query, verbose=0, timeout=5)

    if answer is None:
        print("Request timeout")
        return None
    
    return answer[DNS]

def parse_ns_records(dns_answer: any, resolver_address: str):
    output = {}

    if dns_answer.qdcount == 0:
        # Query incompleta ?
        return output

    query_name = dns_answer.qd[0].qname.decode("utf-8")

    for x in range(dns_answer.nscount):
        
        record_name = dns_answer.ns[x].rrname.decode("utf-8")

        if record_name != query_name:
            continue

        record_data = dns_answer.ns[x].rdata.decode("utf-8")
        record_type = dnstypes[dns_answer.ns[x].type]
        record_class = dnsclasses[dns_answer.ns[x].rclass]

        output[record_data] = {
            "rtype": record_type,
            "rclass": record_class,
            "rrname": record_name,
            "rdata": record_data,
            "a_record": None
        }
    
    for x in range(dns_answer.ancount):
        record_name = dns_answer.an[x].rrname.decode("utf-8")
        record_type = dnstypes[dns_answer.an[x].type]

        if record_type != "NS" or record_name != query_name:
            continue

        record_data = dns_answer.an[x].rdata.decode("utf-8")
        record_class = dnsclasses[dns_answer.an[x].rclass]

        output[record_data] = {
            "rtype": record_type,
            "rclass": record_class,
            "rrname": record_name,
            "rdata": record_data,
            "a_record": None
        }

    # Iterar sobre el diccionario generado agregando una direccion IP a cada registro NS
    for k, v in list(output.items()):
        if v["a_record"] is None:
            dns_answer = resolve_dns(k, resolver_address, "A", True)
            ip_address = dns_answer.an[0].rdata if dns_answer.ancount > 0 else None
            if ip_address is None:  # No se encontraron registros A para el NS
                output.pop(k)       # Eliminarlo del diccionario
            else:
                v["a_record"] = ip_address

    return output

def trace(fqdn: str, dns_address: str):
    '''
    Retorna los registros asociados a un FQDN
    :param: fqdn String con el valor del FQDN
    :param: dns_address Dirección IP del servidor DNS a consultar
    '''

    trace_string: str = ""

    split_fqdn: list[str] = fqdn.split(".")
    split_fqdn[-1] += "."

    index_list = list(reversed(range(len(split_fqdn))))
    if len(index_list) > 0:
        index_list.pop()

    print("-------------------------------------------------------")
    print(f'FQDN: {fqdn}')
    print("-------------------------------------------------------")

    ########################################################################
    # Obtener registros NS para el TLD usando el solucionador DNS provisto #
    ########################################################################
    
    query = split_fqdn[-1]      # TLD
    dns_answer = resolve_dns(query, dns_address, "NS", True)

    if dns_answer is None or dns_answer.ancount == 0:
        print(f'No NS records found for query "{query}"')
        return None
    
    ns_records = parse_ns_records(dns_answer, dns_address)

    if len(ns_records) == 0:
        print(f'No NS records found for query "{query}"')
        return None
    
    # Concatenar los resultados a la string de salida
    for k, v in ns_records.items():
        trace_string += f'{v["rrname"]}    {v["rclass"]}    {v["rtype"]}    {v["rdata"]}    {v["a_record"]}\n'

    trace_string += "-------------------------------------------------------\n"
    trace_string += f'Response from {dns_address}\n'
    trace_string += "-------------------------------------------------------\n"

    # Seleccionar un servidor TLD aleatoriamente
    next_ns_fqdn: str    = random.choice(list(ns_records.keys()))
    next_ns_address: str = ns_records[next_ns_fqdn]["a_record"]

    #####################################################################
    # Buscar iterativamente el fqdn a partir del servidor TLD elegido #
    #####################################################################

    # Genera una lista de la forma ["d1.tld", "d2.d1.tld", "d3.d2.d1.tld", ...] a partir del fqdn
    query_list = []
    for i in list(reversed(range(len(split_fqdn) - 1))):
        query_list.append(".".join(split_fqdn[i:]))
    query_list.pop()

    for qname in query_list:

        # Obtener los registros NS para la query actual
        dns_answer = resolve_dns(qname, next_ns_address, "NS", False)

        ns_records = parse_ns_records(dns_answer, dns_address)

        if len(ns_records) == 0:
            print(f'No NS records found for query "{qname}"')
            break
        
        # Concatenar los resultados a la string de salida
        for k, v in ns_records.items():
            trace_string += f'{v["rrname"]}    {v["rclass"]}    {v["rtype"]}    {v["rdata"]}    {v["a_record"]}\n'

        trace_string += "-------------------------------------------------------\n"
        trace_string += f'Response from {next_ns_address} ({next_ns_fqdn})\n'
        trace_string += "-------------------------------------------------------\n"

        next_ns_fqdn: str    = random.choice(list(ns_records.keys()))
        next_ns_address: str = ns_records[next_ns_fqdn]["a_record"]

    # Obtener todos los registros desde el servidor autoritativo
    #for index, rtype in list(dnstypes.items()):

    #if rtype in ["ANY", "NS"]:
    #    continue

    #print(rtype)

    dns_answer = resolve_dns(fqdn, next_ns_address, "A", False)

    #if dns_answer is None:
    #    continue
    
    for x in range(dns_answer.ancount):
        record_data = dns_answer.an[x].rdata
        if type(record_data) == bytes:
            try:
                record_data = record_data.decode("utf-8")
            except UnicodeDecodeError:
                continue
        
        record_type = dnstypes[dns_answer.an[x].type]
        record_class = dnsclasses[dns_answer.an[x].rclass]
        
        trace_string += f'{fqdn}     {record_class}      {record_type}      {record_data}\n'

    trace_string += "-------------------------------------------------------\n"
    trace_string += f'Response from {next_ns_address} ({next_ns_fqdn})\n'
    trace_string += "-------------------------------------------------------\n"

    print(trace_string)

def get_main_nameserver():
    """
    Retorna el primer nameserver del archivo /etc/resolv.conf
    :returns: Dirección IP del nameserver o None en caso de que no exista un valor
    """
    ns_list = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as config_file:
            for line in config_file.readlines():
                line = line.lstrip()
                
                if line.startswith("#"):
                    continue
        
                if "nameserver" in line:
                    ns_list.append(line.split()[1])   # Extraer la dirección IP
        
        return ns_list[0] if len(ns_list) > 0 else None
    except Exception:
        return None

if __name__ == "__main__":
    main()
