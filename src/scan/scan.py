from scapy import all as scapy
import socket
import requests
from helper.helper import get_service, parametres


def arp_scan(ip):
    request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    ans, unans = scapy.srp(request, timeout=2, retry=1)
    result  = "undefinded"

    for sent, received in ans:
        result = received.hwsrc

    return result


def tcp_scan(ip, ports):
    try:
        syn = scapy.IP(dst=ip) / scapy.TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    ans, unans = scapy.sr(syn, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        if received[scapy.TCP].flags == "SA":
            result.append(received[scapy.TCP].sport)

    return result

def get_country_provider(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token=394fe6b1d28d1a")
        data = response.json()
        country = data.get("country", "Unknown")
        provider = data.get("org", "Unknown")
        return country, provider
    except Exception as e:
        return "Unknown", "Unknown"

def scan_network(ip_adresses, ports, parametres: parametres):
    print(ip_adresses, ports)
    for ip_address in ip_adresses:
        
        service = list()
        
        open_ports = tcp_scan(ip_address, ports)
        mac_address = arp_scan(ip_address)
        country, provider = get_country_provider(ip_address)
        
        for port in open_ports:
            service = get_service(port)
            parametres.all_information.loc[len(parametres.all_information.index)] = [ip_address, mac_address, country, provider, port, service]
            print([ip_address, mac_address, country, provider, port, service])
        
    parametres.copy()