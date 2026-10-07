import socket
import sys
from concurrent.futures import ThreadPoolExecutor

open_ports = []

services = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8000: "Python HTTP Server"
}


def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((target, port))

    if result == 0:
        service = services.get(port, "Unknown")
        open_ports.append(port)
        print(f"\nOpen Ports Found: {len(open_ports)}")
        print(f"[OPEN] Port {port} ({service})")

    sock.close()


if len(sys.argv) != 4:
    print("Usage:")
    print("python scanner.py <target> <start_port> <end_port>")
    sys.exit()

target = sys.argv[1]
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

print("=" * 40)
print("Threaded Port Scanner")
print(f"Target: {target}")
print(f"Range : {start_port}-{end_port}")
print("=" * 40)

with ThreadPoolExecutor(max_workers=100) as executor:
    for port in range(start_port, end_port + 1):
        executor.submit(scan_port, target, port)

print("\nScan Complete")
