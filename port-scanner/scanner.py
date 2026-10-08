import argparse
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "Python HTTP Server",
    8080: "HTTP Alternate",
}


def validate_target(target):
    """
    Resolve a hostname and ensure the target is a private
    or local IP address.
    """

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError(f"Could not resolve target: {target}") from error

    try:
        address = ipaddress.ip_address(resolved_ip)
    except ValueError as error:
        raise ValueError("The resolved target is not a valid IP address.") from error

    if address.is_multicast:
        raise ValueError("Multicast addresses are not allowed.")

    if address.is_unspecified:
        raise ValueError("Unspecified addresses are not allowed.")

    if address.is_reserved:
        raise ValueError("Reserved addresses are not allowed.")

    if address.is_link_local:
        raise ValueError("Link-local addresses are not allowed.")

    if not (address.is_private or address.is_loopback):
        raise ValueError(
            "This learning version only scans localhost or private IP addresses."
        )

    return resolved_ip


def validate_ports(start_port, end_port):
    """Validate the requested TCP port range."""

    if not 1 <= start_port <= 65535:
        raise ValueError("Start port must be between 1 and 65535.")

    if not 1 <= end_port <= 65535:
        raise ValueError("End port must be between 1 and 65535.")

    if start_port > end_port:
        raise ValueError("Start port cannot be greater than end port.")

    number_of_ports = end_port - start_port + 1

    if number_of_ports > 10001:
        raise ValueError(
            "This version can scan a maximum of 10,001 ports at a time."
        )


def scan_port(target_ip, port, timeout):
    """Attempt a TCP connection to one port."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                return {
                    "port": port,
                    "service": SERVICES.get(port, "Unknown"),
                    "status": "open",
                }

    except OSError:
        return None

    return None


def save_text_report(scan_result):
    """Save scan results as a readable text file."""

    filename = "scan-report.txt"

    with open(filename, "w", encoding="utf-8") as report:
        report.write("CYBER LAB PORT SCANNER REPORT\n")
        report.write("=" * 50 + "\n")
        report.write(f"Target: {scan_result['target']}\n")
        report.write(f"Resolved IP: {scan_result['resolved_ip']}\n")
        report.write(
            f"Port range: "
            f"{scan_result['start_port']}-{scan_result['end_port']}\n"
        )
        report.write(f"Scan time: {scan_result['scan_time']}\n")
        report.write(
            f"Duration: {scan_result['duration_seconds']} seconds\n"
        )
        report.write(
            f"Open ports found: {len(scan_result['open_ports'])}\n"
        )
        report.write("=" * 50 + "\n")

        if not scan_result["open_ports"]:
            report.write("No open ports were found.\n")
        else:
            for item in scan_result["open_ports"]:
                report.write(
                    f"Port {item['port']}: "
                    f"OPEN ({item['service']})\n"
                )

    return filename


def save_json_report(scan_result):
    """Save structured scan results in JSON format."""

    filename = "scan-report.json"

    with open(filename, "w", encoding="utf-8") as report:
        json.dump(scan_result, report, indent=4)

    return filename


def create_parser():
    """Create and configure the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description=(
            "A threaded TCP port scanner for authorized local "
            "and private-network testing."
        )
    )

    parser.add_argument(
        "target",
        help="Target hostname or private IP address",
    )

    parser.add_argument(
        "start_port",
        type=int,
        help="First TCP port to scan",
    )

    parser.add_argument(
        "end_port",
        type=int,
        help="Last TCP port to scan",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout in seconds, default: 0.5",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Number of scanner threads, default: 100",
    )

    parser.add_argument(
        "--save",
        choices=["text", "json", "both"],
        help="Save results as text, JSON, or both",
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    try:
        validate_ports(args.start_port, args.end_port)

        if not 0.1 <= args.timeout <= 5.0:
            raise ValueError(
                "Timeout must be between 0.1 and 5 seconds."
            )

        if not 1 <= args.workers <= 200:
            raise ValueError(
                "Workers must be between 1 and 200."
            )

        target_ip = validate_target(args.target)

    except ValueError as error:
        print(f"[ERROR] {error}")
        return

    print("=" * 50)
    print("CYBER LAB PORT SCANNER v1.0")
    print("=" * 50)
    print(f"Target       : {args.target}")
    print(f"Resolved IP  : {target_ip}")
    print(f"Port range   : {args.start_port}-{args.end_port}")
    print(f"Threads      : {args.workers}")
    print(f"Timeout      : {args.timeout} seconds")
    print("=" * 50)

    started = time.perf_counter()
    open_ports = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        jobs = [
            executor.submit(
                scan_port,
                target_ip,
                port,
                args.timeout,
            )
            for port in range(args.start_port, args.end_port + 1)
        ]

        for job in as_completed(jobs):
            result = job.result()

            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda item: item["port"])

    duration = round(time.perf_counter() - started, 3)

    if open_ports:
        for item in open_ports:
            print(
                f"[OPEN] {item['port']:<5} "
                f"{item['service']}"
            )
    else:
        print("No open ports found in the selected range.")

    scan_result = {
        "target": args.target,
        "resolved_ip": target_ip,
        "start_port": args.start_port,
        "end_port": args.end_port,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": duration,
     "open_ports": open_ports,
    }

    print("=" * 50)
    print(f"Open ports found : {len(open_ports)}")
    print(f"Scan duration    : {duration} seconds")
    print("=" * 50)

    if args.save in ("text", "both"):
        filename = save_text_report(scan_result)
        print(f"Text report saved: {filename}")

    if args.save in ("json", "both"):
        filename = save_json_report(scan_result)
        print(f"JSON report saved: {filename}")


if __name__ == "__main__":
    main()