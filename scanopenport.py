#!/usr/bin/python3

import socket
import pyfiglet
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from tqdm import tqdm
from termcolor import colored

# Prints logo
logo_text = pyfiglet.figlet_format("Port Scanner")
print(logo_text)

# Constants
ADDRESS_FAMILY = socket.AF_INET
SOCKET_TYPE = socket.SOCK_STREAM
TIMEOUT = 0.5  # socket timeout in seconds

# Define port scanner function
def portScanner(task):
    target_ip, port, pbar = task
    with socket.socket(ADDRESS_FAMILY, SOCKET_TYPE) as s:
        s.settimeout(TIMEOUT)
        try:
            result = s.connect_ex((target_ip, port))
            if result == 0:
                return f"Port {port} is open on {target_ip}"
        except socket.error:
            pass  # do not print anything if the port is closed
    pbar.update(1)
    return None

# Gets user input and removes any carriage return characters from the input, if the code is running on Windows OS
if os.name == 'nt': 
    subnet = input("Please enter the Target IP Subnet (e.g., 192.168.0.0/24): ").replace('\r', '') 
    port_range = input("Please enter the port range to scan (e.g., 8000-9000): ").replace('\r', '')
else:
    subnet = input("Please enter the Target IP Subnet (e.g., 192.168.0.0/24): ")
    port_range = input("Please enter the port range to scan (e.g., 8000-9000): ")

# Split port range into start_port and end_port
try:
    start_port, end_port = map(int, port_range.split('-'))
except ValueError:
    print("Invalid port range format. Please use format like '8000-8800'.")
    exit()

# Parse subnet input to obtain list of IP addresses
try:
    network = ipaddress.ip_network(subnet)
except ValueError as e:
    print("Invalid subnet:", e)
    exit()

# Define max_workers for ThreadPoolExecutor
max_workers = multiprocessing.cpu_count() * 500  # Using 500x CPU cores for max_workers

# Calculate total tasks for progress bar
total_tasks = len(network.hosts()) * (end_port - start_port + 1)

# Create progress bar
pbar = tqdm(total=total_tasks, ncols=70, unit="task")

# Create ThreadPoolExecutor instance
open_ports = []
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    # Prepare tasks
    tasks = [(str(ip_address), port, pbar) for ip_address in network.hosts() for port in range(start_port, end_port + 1)]
    # Submit tasks
    results = executor.map(portScanner, tasks)
    # Collect open ports
    open_ports = [result for result in results if result is not None]

# Close progress bar
pbar.close()

# Print open ports
for open_port in open_ports:
    print(colored(open_port, 'green'))

print("\nScanning completed.")  # New line before this message
