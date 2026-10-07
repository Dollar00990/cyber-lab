import socket

target = input("Enter target IP: ")

print(f"\nScanning {target}...\n")

for port in range(7995, 8006):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)

    result = sock.connect_ex((target, port))

    if result == 0:
        print(f"Port {port} is OPEN")

    sock.close()

print("\nScan completed.")