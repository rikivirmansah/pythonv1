from pysnmp.hlapi import *
import ipaddress
import concurrent.futures
from tqdm import tqdm
from colorama import Fore, Style

def check_snmp(ip):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData('public'),  # Ganti 'public' dengan community string Anda
               UdpTransportTarget((str(ip), 161)),  # Ganti 'ip_routeros' dengan IP MikroTik Anda
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
    )

    if errorIndication or errorStatus:
        return None  # Jika ada error, abaikan
    else:
        for varBind in varBinds:
            return str(ip), ' = '.join([x.prettyPrint() for x in varBind])  # Mengembalikan alamat IP dan identitas

def is_public(ip):
    # Fungsi untuk memeriksa apakah alamat IP adalah alamat IP publik atau bukan
    return not (ipaddress.ip_address(ip).is_private)

def scan_network(network):
    # Define your IP range
    ip_network = ipaddress.ip_network(network)

    # Create a list of all subnets that we need to scan
    if ip_network.prefixlen < 24:
        subnets = list(ip_network.subnets(new_prefix=24))
    else:
        subnets = [ip_network]

    # Create a ProcessPoolExecutor
    with concurrent.futures.ProcessPoolExecutor() as executor:
        # For each subnet, get a list of all hosts and check each one
        for subnet in subnets:
            ip_list = list(subnet.hosts())
            results = list(tqdm(executor.map(check_snmp, ip_list), total=len(ip_list)))

            # Print the results
            for result in results:
                if result is not None and is_public(result[0]):
                    print(Fore.GREEN + str(result) + Style.RESET_ALL)

if __name__ == "__main__":
    # Use the function with your desired network
    network = input("Please enter the network range (e.g., '192.168.1.0/24'): ")
    scan_network(network)
