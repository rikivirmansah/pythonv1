import os
import concurrent.futures
import ipaddress
import time
import threading

# Ask the user for the network to scan
network_input = input("Please enter the network (e.g., '192.168.1.0/24'): ")
network = ipaddress.ip_network(network_input)

# Generate a list of all IPs in the network
ip_list = [ip for ip in network.hosts()]

# Function to ping an IP and check if it's up
def ping(ip):
    # Use the ping command and suppress output
    response = os.system("ping -n 1 -w 1 " + str(ip) + " > NUL 2>&1")

    # Check if the ping was successful
    if response == 0:
        return ip

# Function to display a loading animation
def loading_animation():
    animation = "|/-\\"
    idx = 0
    while not done:
        print(animation[idx % len(animation)], end="\r")
        idx += 1
        time.sleep(0.1)

# Flag to indicate when the scanning is done
done = False

# Start the loading animation in a separate thread
animation_thread = threading.Thread(target=loading_animation)
animation_thread.start()

# Use a ThreadPoolExecutor to ping all IPs in parallel
alive_ips = []
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    futures = executor.map(ping, ip_list)
    for result in futures:
        if result is not None:
            alive_ips.append(result)

# Indicate that the scanning is done
done = True

# Wait for the animation thread to finish
animation_thread.join()

# Print the IPs that are up
print("IPs that are up:")
for ip in alive_ips:
    print(ip)
