#!/usr/bin/python3

import subprocess
import sys

# Function to install a package
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Required libraries
required_libraries = ["socket", "pyfiglet", "os", "ipaddress", "tqdm", "termcolor"]

# Install missing libraries
for library in required_libraries:
    try:
        __import__(library)
    except ImportError:
        install(library)

# Imports (after ensuring the libraries are installed)
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
    target_ip, port = task
    with socket.socket(ADDRESS_FAMILY, SOCKET_TYPE) as s:
        s.settimeout(TIMEOUT)
        try:
            result = s.connect_ex((target_ip, port))
            if result == 0:
                return f"Port {port} is open on {target_ip}"
        except socket.error:
            pass  # do not print anything if the port is closed
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
total_tasks = len(list(network.hosts())) * (end_port - start_port + 1)

# Create progress bar
pbar = tqdm(total=total_tasks, ncols=70, unit="task")

# Create ThreadPoolExecutor instance
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    # Prepare tasks
    tasks = [(str(ip_address), port) for ip_address in network.hosts() for port in range(start_port, end_port + 1)]
    # Submit tasks and process results in real-time
    for result in executor.map(portScanner, tasks):
        pbar.update(1)  # Update progress bar after each task
        if result:  # If a port is found open
            print(colored(result, 'green'))

# Close progress bar
pbar.close()

print("\nScanning completed.")  # New line before this message
