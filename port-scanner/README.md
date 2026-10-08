# Cyber Lab Port Scanner

A multithreaded TCP port scanner written in Python for learning network programming and authorized security testing.

## Safety Notice

Only scan computers and networks that you own or have explicit permission to test.

This learning version restricts scanning to localhost and private IP addresses.

## Features

- TCP connect scanning
- Multithreaded scanning
- Custom port ranges
- Hostname resolution
- Common service identification
- Configurable timeout
- Configurable worker threads
- Text report export
- JSON report export
- Input and target validation

## Requirements

- Python 3.10 or newer
- No external Python packages required

## Usage

Basic syntax:

```bash
python scanner.py <target> <start_port> <end_port>
```

Scan a local port range:

```bash
python scanner.py 127.0.0.1 7990 8010
```

Save a text report:

```bash
python scanner.py 127.0.0.1 7990 8010 --save text
```

Save a JSON report:

```bash
python scanner.py 127.0.0.1 7990 8010 --save json
```

Save both report formats:

```bash
python scanner.py 127.0.0.1 7990 8010 --save both
```

Change the timeout:

```bash
python scanner.py 127.0.0.1 7990 8010 --timeout 1
```

Change the number of worker threads:

```bash
python scanner.py 127.0.0.1 7990 8010 --workers 50
```

Display help:

```bash
python scanner.py --help
```

## Testing

Start a temporary local web server:

```bash
python -m http.server 8000
```

Open another terminal and scan the port:

```bash
python scanner.py 127.0.0.1 7990 8010
```

Example output:

```text
==================================================
CYBER LAB PORT SCANNER v1.0
==================================================
Target       : 127.0.0.1
Resolved IP  : 127.0.0.1
Port range   : 7990-8010
Threads      : 100
Timeout      : 0.5 seconds
==================================================
[OPEN] 8000  Python HTTP Server
==================================================
Open ports found : 1
Scan duration    : 0.021 seconds
==================================================
```

## Project Structure

```text
port-scanner/
├── README.md
├── scanner.py
└── requirements.txt
```

Generated scan reports are excluded from GitHub because they may contain network information.

## Current Limitations

- Supports TCP connect scanning only
- Supports IPv4 only
- Scans localhost and private IP addresses only
- Service names are based on a small built-in mapping
- Does not determine software versions
- Does not determine whether a firewall filtered a port

## Planned Improvements

- Web API using FastAPI
- Browser-based dashboard
- Scan history
- Authentication
- Configurable target allowlist
- Container deployment
- Authorized private-cloud scanning

## Author

Lebakae Amose Adoro