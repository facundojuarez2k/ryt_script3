import random
import argparse
import re
import sys
import logging
# Suprimir warnings en stdout
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
from scapy.all import IP, UDP, DNS, DNSQR
# Importar diccionario de DNS record types y classes
from scapy.layers.dns import dnstypes, dnsclasses

FALLBACK_DNS = "8.8.8.8"


def main():

    resolver_address: str = get_main_nameserver()

    if resolver_address is None or test_resolver(resolver_address) == False:
        resolver_address = FALLBACK_DNS

    try:
        args = parse_args()
        fqdn = args.fqdn
        test_fqdn_tld(fqdn, resolver_address)
    except ValueError as ex1:
        print(f'ERROR: {str(ex1)}', file=sys.stderr)
        sys.exit(1)

    trace(fqdn, resolver_address)


def trace(fqdn: str, dns_address: str) -> None:
    """Imprime la traza de la consulta iterativa para el fqdn indicado en el argumento

    Args:
        fqdn (str): FQDN a consultar
        dns_address (str): Dirección IPv4 del solucionador DNS inicial
    """

    fqdn = fqdn.strip(".")
    split_fqdn: list[str] = fqdn.split(".")
    split_fqdn[-1] += "."

    trace_string: str = divider(f'FQDN: {fqdn}')

    # Genera una lista de la forma [".", "tld", "d1.tld", "d2.d1.tld", ...] a partir del fqdn
    query_list = ["."]
    for i in list(reversed(range(len(split_fqdn)))):
        query_list.append(".".join(split_fqdn[i:]))

    next_ns_fqdn: str = ""
    next_ns_address = dns_address

    for qname in query_list:

        recursive_lookup = qname == "." # Consulta recursiva solo en la primera iteración
        
        # Obtener los registros NS para la query actual
        dns_answer = resolve_dns(qname, next_ns_address, "NS", recursive_lookup)

        if dns_answer is None:
            print("Request timeout")
            return None

        ns_records = parse_ns_records(dns_answer, dns_address)

        if len(ns_records) == 0:
            break

        # Concatenar los resultados a la string de salida
        for _, v in ns_records.items():
            trace_string += f'{v["rrname"]:20s} {v["rclass"]:5s} {v["rtype"]:5s} {v["rdata"]:30s} {v["a_record"]:10s}\n'

        trace_string += divider(
            f'Response from {next_ns_address} {("("+next_ns_fqdn+")") if next_ns_fqdn != "" else ""}')

        # Seleccionar el siguiente nameserver a consultar de forma aleatoria
        next_ns_fqdn: str = random.choice(list(ns_records.keys()))
        next_ns_address: str = ns_records[next_ns_fqdn]["a_record"]

    # Obtener los RR para el FQDN a partir del nameserver autoritativo
    query = ".".join(split_fqdn)
    dns_answer = resolve_dns(query, next_ns_address, "A", False)

    if dns_answer is None:
        print("Request timeout")
        return None

    if (dns_answer.ancount > 0):
        for x in range(dns_answer.ancount):
            record_type = dnstypes[dns_answer.an[x].type]
            record_class = dnsclasses[dns_answer.an[x].rclass]

            record_data = dns_answer.an[x].rdata
            if type(record_data) == bytes:
                record_data = record_data.decode("utf-8")

            trace_string += f'{query:20s} {record_class:5s} {record_type:10s} {record_data:30s}\n'

        trace_string += divider(
            f'Response from {next_ns_address} ({next_ns_fqdn})')
        
        print(trace_string)
    else:
        print(f'No A or CNAME records found for {query}')
    

def resolve_dns(query: str, dns_address: str, record_type: str, recursive_lookup: bool = False, record_class: str = "IN") -> any:
    """Retorna la respuesta de Scapy para una consulta directa a un servidor DNS

    Args:
        query (str): Consulta a realizar
        dns_address (str): Dirección IPv4 del servidor DNS a consultar
        record_type (str): Tipo de registro DNS
        recursive_lookup (bool, optional): Determina si la busqueda debe hacerse recursivamente. Default: False.
        record_class (str, optional): Clase del reigstro. Default: "IN".

    Returns:
        any: Objeto de clase scapy.layers.dns.DNS con la respuesta obtenida
    """

    ip_packet = IP(dst=dns_address)
    udp_segment = UDP(sport=scapy.RandShort(), dport=53)
    dns_query = DNS(
        rd=recursive_lookup,
        qd=DNSQR(qname=query, qtype=record_type, qclass=record_class),
    )

    answer = scapy.sr1(ip_packet/udp_segment/dns_query, verbose=0, timeout=5)

    if answer is None:
        return None

    return answer[DNS]


def parse_ns_records(dns_answer: any, resolver_address: str) -> dict:
    """Retorna un diccionario con el fqdn del nameserver como clave y los campos del registro como valor.

    Args:
        dns_answer (any): Objeto clase Packet retornado por Scapy
        resolver_address (str): Dirección IPv4 del nameserver a consultar

    Returns:
        dict: Diccionario
    """
    output = {}

    if dns_answer.qdcount == 0:
        return output

    query_name = dns_answer.qd[0].qname.decode("utf-8")

    # Obtener los registros NS desde la propiedad ns de la respuesta de Scapy
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

    # Obtener los registros NS desde la propiedad an de la respuesta de Scapy
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
            ip_address = None
            
            if dns_answer is not None and dns_answer.ancount > 0 and dns_answer[0] is not None:
                ip_address = dns_answer.an[0].rdata
            
            if ip_address is None:  # No se encontraron registros A para el NS
                output.pop(k)       # Eliminarlo del diccionario
            else:
                v["a_record"] = ip_address

    return output


def parse_args() -> object:
    """Captura y retorna los argumentos del programa

    Returns:
        object: argumentos
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''DNS Trace \n\nGiven a valid FQDN, prints the trace generated by iteratively querying the nameservers''')
    parser.add_argument(dest='fqdn', type=str, help='Fully qualified domain name')

    validate_args(parser.parse_args())

    return parser.parse_args()


def validate_args(args: object) -> None:
    """Valida los argumentos del programa

    Args:
        args (object): argparse.args

    Raises:
        ValueError: Si el argumento no es válido
    """
    if is_valid_fqdn_syntax(args.fqdn) is False:
        raise ValueError(f'Value {args.fqdn} is not a valid FQDN string.')


def is_valid_fqdn_syntax(value: str) -> bool:
    """Retorna True si value representa un FQDN

    Args:
        value (str): Valor de entrada

    Returns:
        bool: True si value es un FQDN, False caso contrario.
    """
    valid_string = re.compile(
        r"(?=^.{4,253}\.?$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)")
    match = re.fullmatch(valid_string, value)
    return match is not None


def test_fqdn_tld(fqdn: str, resolver_address: str):
    """Verifica que el TLD del FQDN sea válido

    Args:
        fqdn (str): FQDN
        resolver_address (str): Dirección IPv4 del solucionador DNS

    Raises:
        ValueError: Si el TLD no existe
    """
    tld = fqdn.split(".")[-1] + "."
    dns_answer = resolve_dns(tld, resolver_address, "NS", True)

    if dns_answer.ancount == 0:
        raise ValueError("FQDN no válido")


def get_main_nameserver() -> any:
    """Retorna el primer nameserver del archivo /etc/resolv.conf
    
    Returns:
        any: Dirección IP del nameserver o None en caso de que el archivo no contenga un valor
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


def test_resolver(resolver_address: str) -> bool:
    """Verifica que el cliente DNS pasado como parámetro funcione correctamente.

    Args:
        resolver_address (str): Dirección IPv4 del solucionador

    Returns:
        bool: True si el solucionador DNS obtiene una respuesta para una consulta de prueba. Falso caso contrario.
    """
    answer = resolve_dns("google.com", resolver_address, "A", True)
    return answer is not None


def divider(content: str) -> str:
    string = ("-" * 80) + "\n"
    string += f'{content}\n'
    string += ("-" * 80) + "\n"
    return string

if __name__ == "__main__":
    main()
