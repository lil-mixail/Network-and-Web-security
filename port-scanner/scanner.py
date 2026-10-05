import argparse
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def scan_port(host, port, timeout=0.5):
    """Return the port number if the TCP port is open, otherwise None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) == 0:
            return port
    return None


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


def get_service(port):
    """Guess the service name from the port number."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"

    
def grab_banner(host, port, timeout=2.0):
    """Try to read a service banner. Returns a short string or ''."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            try:
                data = s.recv(1024)  # SSH, FTP, SMTP speak first
            except socket.timeout:
                data = b""
            if not data:
                # HTTP waits for the client, so send a minimal request
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = s.recv(1024)
    except OSError:
        return ""

    text = data.decode(errors="ignore").strip()
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            return line.strip()
    return text.splitlines()[0] if text else ""

def main():
    parser = argparse.ArgumentParser(description="Multithreaded TCP port scanner")
    parser.add_argument("target", help="IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="e.g. 22,80 or 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=0.5)
    parser.add_argument("-w", "--workers", type=int, default=100, help="number of threads")
    args = parser.parse_args()

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"Error: cannot resolve host '{args.target}'")

    ports = parse_ports(args.ports)
    print(f"Scanning {args.target} ({ip}), {len(ports)} ports, {args.workers} threads...")

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = executor.map(lambda p: scan_port(ip, p, args.timeout), ports)
    open_ports = [p for p in results if p is not None]
    elapsed = time.perf_counter() - start

    for port in open_ports:
        banner = grab_banner(args.target, port)
        print(f"[OPEN] {port}/tcp  {get_service(port):<8} {banner}")


if __name__ == "__main__":
    main()