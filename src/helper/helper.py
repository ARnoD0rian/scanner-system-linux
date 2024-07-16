import pandas as pd

def get_service(port):
    services = {
    7: 'Echo',
    19: 'CHARGEN',
    20: 'FTP-data',
    21: 'FTP',
    22: 'SSH/SCP/SFTP',
    23: 'Telnet',
    25: 'SMTP',
    42: 'WINS Replication',
    43: 'WHOIS',
    49: 'TACACS',
    53: 'DNS',
    70: 'Gopher',
    79: 'Finger',
    80: 'HTTP',
    88: 'Kerberos',
    102: 'Microsoft Exchange ISO-TSAP',
    110: 'POP3',
    113: 'Ident',
    119: 'NNTP (Usenet)',
    135: 'Microsoft RPC EPMAP',
    137: 'NetBIOS-ns',
    138: 'NetBIOS-dgm',
    139: 'NetBIOS-ssn',
    143: 'IMAP',
    161: 'SNMP-agents (unencrypted)',
    162: 'SNMP-trap (unencrypted)',
    177: 'XDMCP',
    179: 'BGP',
    194: 'IRC',
    201: 'AppleTalk',
    264: 'BGMP',
    318: 'TSP',
    381: 'HP Openview',
    383: 'HP Openview',
    389: 'LDAP',
    411: '(Multiple uses)',
    412: '(Multiple uses)',
    427: 'SLP',
    443: 'HTTPS (HTTP over SSL)',
    445: 'Microsoft DS SMB',
    464: 'Kerberos',
    465: 'SMTP over TLS/SSL, SSM',
    497: 'Dantz Retrospect',
    500: 'IPSec / ISAKMP / IKE',
    512: 'rexec',
    513: 'rlogin',
    514: 'syslog',
    515: 'LPD/LPR',
    520: 'RIP',
    521: 'RIPng (IPv6)',
    540: 'UUCP',
    548: 'AFP',
    554: 'RTSP',
    546: 'DHCPv6',
    547: 'DHCPv6',
    560: 'rmonitor',
    563: 'NNTP over TLS/SSL',
    587: 'SMTP',
    591: 'FileMaker',
    593: 'Microsoft DCOM',
    596: 'SMSD',
    631: 'IPP',
    636: 'LDAP over TLS/SSL',
    639: 'MSDP (PIM)',
    646: 'LDP (MPLS)',
    691: 'Microsoft Exchange',
    860: 'iSCSI',
    873: 'rsync',
    902: 'VMware Server',
    989: 'FTPS',
    990: 'FTPS',
    993: 'IMAP over SSL (IMAPS)',
    995: 'POP3 over SSL (POP3S)'
    }

    return services.get(port, "Unknown")

class parametres:
    def __init__(self) -> None:
        
        self.output = pd.DataFrame({
            "ip_adresses": [],
            "mac_adresses": [],
            "countries": [],
            "providers": [],
            "port": [],
            "services": []
        })
        
        self.all_information = pd.DataFrame({
            "ip_adresses": [],
            "mac_adresses": [],
            "countries": [],
            "providers": [],
            "port": [],
            "services": []
        })
        
        self.scan_ip_adresses = []
        self.scan_ports = []
    
    def copy(self):
        self.output = self.all_information.copy()
        
    def filter_atribute(self, atribute, filter_name):
        self.output = self.output.loc[self.output[atribute].isin(filter_name)]
        
    def clear_information(self):
        self.output = pd.DataFrame({
            "ip_adresses": [],
            "mac_adresses": [],
            "countries": [],
            "providers": [],
            "port": [],
            "services": []
        })
        
        self.all_information = pd.DataFrame({
            "ip_adresses": [],
            "mac_adresses": [],
            "countries": [],
            "providers": [],
            "port": [],
            "services": []
        })