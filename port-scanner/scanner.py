import socket
import sys

services = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    8000: "Python HTTP Server"
}

if len(sys.argv) != 4:
    print("Usage:")
    print("python scanner.py <target> <start_port> <end_port>")
    sys.exit()

target = sys.argv[1]
start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

print("=" * 40)
print("Simple Port Scanner")
print(f"Target: {target}")
print(f"Range : {start_port}-{end_port}")
print("=" * 40)

open_ports = []

for port in range(start_port, end_port + 1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((target, port))

    if result == 0:
        service = services.get(port, "Unknown")
        print(f"[OPEN] Port {port} ({service})")
        open_ports.append(port)

    sock.close()

print("\nScan Complete")
print(f"Open Ports Found: {len(open_ports)}")