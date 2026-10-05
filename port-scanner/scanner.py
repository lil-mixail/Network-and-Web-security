import argparse
import socket


def scan_port(host, port, timeout=0.5):
    """Return True if the TCP port is open (full connect scan)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def parse_ports(spec):
    """Parse '22,80,443' or '1-1024' or a mix of both."""
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(description="Simple TCP port scanner")
    parser.add_argument("target", help="IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="e.g. 22,80 or 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=0.5)
    args = parser.parse_args()

    ip = socket.gethostbyname(args.target)
    ports = parse_ports(args.ports)
    print(f"Scanning {args.target} ({ip}), {len(ports)} ports...")

    for port in ports:
        if scan_port(ip, port, args.timeout):
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            print(f"[OPEN] {port}/tcp  {service}")

    print("Done.")


if __name__ == "__main__":
    main()
