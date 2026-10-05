# Port Scanner

A Python TCP port scanner with two scan modes, multithreading and service detection.
Built as a learning project to understand how tools like Nmap work under the hood.

## Features

- **Connect scan**: full TCP handshake using the `socket` library
- **SYN scan** (half-open): raw packets crafted with **Scapy**, detects `open`, `closed` and `filtered` ports
- **Multithreading** with `ThreadPoolExecutor`: 1024 ports in ~5 seconds
- **Banner grabbing**: identifies services and versions (SSH, HTTP, etc.)
- Flexible port ranges: `22,80,443` or `1-1024` or a mix

## Installation

```bash
git clone git@github.com:lil-mixail/Network-and-Web-security.git
cd Network-and-Web-security
python3 -m venv venv
source venv/bin/activate
pip install scapy
```

## Usage

```bash
# Connect scan (no root needed)
python port-scanner/scanner.py <target> -p 1-1024

# SYN scan (requires root for raw packets)
sudo venv/bin/python port-scanner/scanner.py <target> -p 1-1024 --syn
```

| Option | Description | Default |
|---|---|---|
| `-p`, `--ports` | Ports to scan | `1-1024` |
| `-t`, `--timeout` | Connection timeout (seconds) | `0.5` |
| `-w`, `--workers` | Number of threads | `100` |
| `--syn` | Use SYN scan mode | off |

## Example

```
$ sudo venv/bin/python port-scanner/scanner.py scanme.nmap.org -p 1-1024 --syn
Scanning scanme.nmap.org (45.33.32.156), 1024 ports, mode: SYN...
[OPEN] 22/tcp  ssh      SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
[OPEN] 80/tcp  http     Server: Apache/2.4.7 (Ubuntu)
Closed: 538, filtered: 484
Done: 2 open of 1024 scanned in 6.25s
```

Results were verified against Nmap (`nmap -sS` and `nmap -sV`): open ports and service versions match.

## How it works

**Connect scan** completes the full TCP handshake (SYN → SYN-ACK → ACK).
Reliable, but it creates a full connection that the target service can log.

**SYN scan** sends only the first SYN packet and reads the reply:

| Reply | Port state |
|---|---|
| SYN-ACK | open |
| RST | closed |
| no reply / ICMP error | filtered (firewall) |

The connection is never completed (the kernel sends RST), so the scan is faster and less noisy.

**Banner grabbing**: services like SSH send a greeting on connect.
For HTTP, the scanner sends a `HEAD` request and reads the `Server` header.

## Limitations

- IPv4 only
- SYN scan results inside a VirtualBox NAT network may differ from a direct connection,
  because NAT does not forward raw packets reliably
- Banner grabbing depends on the service exposing a banner

## Legal disclaimer

Only scan systems you own or have explicit permission to test.
`scanme.nmap.org` is provided by the Nmap project for testing.
Unauthorized port scanning may be illegal in your jurisdiction.

## Tech

Python 3 · socket · Scapy · concurrent.futures · argparse