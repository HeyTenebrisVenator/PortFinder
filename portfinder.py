#!/usr/bin/env python3

import argparse
import csv
import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Optional


DEFAULT_PROBES = {
    21: b"\r\n",
    22: b"\r\n",
    23: b"\r\n",
    25: b"EHLO scanner.local\r\n",
    80: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SentinelPortScan/1.0\r\nConnection: close\r\n\r\n",
    110: b"\r\n",
    143: b"\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SentinelPortScan/1.0\r\nConnection: close\r\n\r\n",
    587: b"EHLO scanner.local\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SentinelPortScan/1.0\r\nConnection: close\r\n\r\n",
    8443: b"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: SentinelPortScan/1.0\r\nConnection: close\r\n\r\n",
}


HIGH_EXPOSURE_PORTS = {
    21, 23, 25, 110, 139, 445, 1433, 1521, 2049, 3306,
    3389, 5432, 5900, 6379, 9200, 9300, 11211, 27017
}

ADMIN_PORTS = {
    22, 2222, 3389, 5900, 5985, 5986
}

WEB_PORTS = {
    80, 443, 8000, 8080, 8081, 8443, 8888
}


@dataclass
class ScanResult:
    target: str
    ip: str
    port: int
    status: str
    service: str
    banner: str
    protocol_hint: str
    exposure_score: int
    notes: str
    response_time_ms: float


def parse_ports(port_string: str) -> list[int]:
    ports = set()

    for part in port_string.split(","):
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            start, end = part.split("-", 1)
            start = int(start.strip())
            end = int(end.strip())

            if start > end:
                start, end = end, start

            ports.update(range(max(1, start), min(65535, end) + 1))
        else:
            port = int(part)

            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port: {port}")

            ports.add(port)

    return sorted(ports)


def load_targets(path: str) -> list[str]:
    targets = []

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            target = line.strip()

            if not target or target.startswith("#"):
                continue

            targets.append(normalize_target(target))

    return list(dict.fromkeys(targets))


def normalize_target(target: str) -> str:
    target = target.strip()

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.hostname or target

    return target


def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def get_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def is_tls_port(port: int) -> bool:
    return port in {443, 8443, 9443, 10443}


def sanitize_banner(data: bytes) -> str:
    if not data:
        return ""

    text = data.decode("utf-8", errors="replace")
    text = text.replace("\r", " ").replace("\n", " ")
    return " ".join(text.split())[:500]


def build_probe(port: int, host: str) -> Optional[bytes]:
    probe = DEFAULT_PROBES.get(port)

    if not probe:
        return None

    return probe.replace(b"{host}", host.encode())


def grab_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    sock.settimeout(timeout)

    try:
        try:
            data = sock.recv(1024)

            if data:
                return sanitize_banner(data)
        except socket.timeout:
            pass

        probe = build_probe(port, host)

        if probe:
            sock.sendall(probe)
            data = sock.recv(4096)
            return sanitize_banner(data)

    except Exception:
        return ""

    return ""


def calculate_exposure_score(port: int, banner: str) -> tuple[int, str]:
    score = 10
    notes = []

    if port in HIGH_EXPOSURE_PORTS:
        score += 50
        notes.append("high-risk exposed service")

    if port in ADMIN_PORTS:
        score += 35
        notes.append("remote administration service")

    if port in WEB_PORTS:
        score += 15
        notes.append("web service")

    lowered_banner = banner.lower()

    risky_keywords = [
        "ftp",
        "telnet",
        "redis",
        "mongodb",
        "mysql",
        "postgresql",
        "elasticsearch",
        "memcached",
        "rdp",
        "samba",
    ]

    for keyword in risky_keywords:
        if keyword in lowered_banner:
            score += 15
            notes.append(f"banner mentions {keyword}")

    return min(score, 100), "; ".join(notes)


def scan_port(target: str, port: int, timeout: float) -> ScanResult:
    start = time.time()
    ip = resolve_target(target)

    if not ip:
        return ScanResult(
            target=target,
            ip="-",
            port=port,
            status="unresolved",
            service="",
            banner="",
            protocol_hint="",
            exposure_score=0,
            notes="DNS resolution failed",
            response_time_ms=0,
        )

    try:
        family = socket.AF_INET

        with socket.socket(family, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(timeout)
            result = raw_sock.connect_ex((ip, port))

            if result != 0:
                return ScanResult(
                    target=target,
                    ip=ip,
                    port=port,
                    status="closed",
                    service=get_service_name(port),
                    banner="",
                    protocol_hint="",
                    exposure_score=0,
                    notes="",
                    response_time_ms=(time.time() - start) * 1000,
                )

            sock = raw_sock
            protocol_hint = "tcp"

            if is_tls_port(port):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(raw_sock, server_hostname=target)
                    protocol_hint = "tls"
                except ssl.SSLError:
                    protocol_hint = "tcp"

            banner = grab_banner(sock, target, port, timeout)
            service = get_service_name(port)

            if banner.startswith("HTTP/"):
                protocol_hint = "http"

            score, notes = calculate_exposure_score(port, banner)

            return ScanResult(
                target=target,
                ip=ip,
                port=port,
                status="open",
                service=service,
                banner=banner,
                protocol_hint=protocol_hint,
                exposure_score=score,
                notes=notes,
                response_time_ms=(time.time() - start) * 1000,
            )

    except Exception as error:
        return ScanResult(
            target=target,
            ip=ip,
            port=port,
            status="error",
            service=get_service_name(port),
            banner="",
            protocol_hint="",
            exposure_score=0,
            notes=str(error),
            response_time_ms=(time.time() - start) * 1000,
        )


def write_csv(results: list[ScanResult], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()

        for result in results:
            writer.writerow(asdict(result))


def write_json(results: list[ScanResult], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump([asdict(result) for result in results], file, indent=2)


def write_txt(results: list[ScanResult], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as file:
        for result in results:
            if result.status == "open":
                file.write(
                    f"{result.target}:{result.port} | "
                    f"{result.service or '-'} | "
                    f"score={result.exposure_score} | "
                    f"{result.banner or '-'}\n"
                )


def save_results(results: list[ScanResult], output_path: str, output_format: str) -> None:
    if not results:
        return

    if output_format == "csv":
        write_csv(results, output_path)
    elif output_format == "json":
        write_json(results, output_path)
    else:
        write_txt(results, output_path)


def detect_output_format(output_path: str, forced_format: Optional[str]) -> str:
    if forced_format:
        return forced_format

    if output_path.endswith(".json"):
        return "json"

    if output_path.endswith(".txt"):
        return "txt"

    return "csv"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Professional TCP port scanner with banner grabbing and exposure scoring"
    )

    target_group = parser.add_mutually_exclusive_group(required=True)

    target_group.add_argument(
        "-t",
        "--target",
        help="Single target hostname or IP address",
    )

    target_group.add_argument(
        "-f",
        "--file",
        help="File containing targets, one per line",
    )

    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help='Ports to scan. Examples: "22,80,443" or "1-1024"',
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Number of worker threads",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.5,
        help="Connection timeout in seconds",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="results.csv",
        help="Output file path",
    )

    parser.add_argument(
        "--format",
        choices=["csv", "json", "txt"],
        default=None,
        help="Force output format",
    )

    parser.add_argument(
        "--only-open",
        action="store_true",
        help="Save only open ports",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    targets = [normalize_target(args.target)] if args.target else load_targets(args.file)
    ports = parse_ports(args.ports)

    if not targets:
        print("[!] No targets provided.")
        sys.exit(1)

    output_format = detect_output_format(args.output, args.format)

    total_tasks = len(targets) * len(ports)

    print("[*] Sentinel PortScan started")
    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Ports: {len(ports)}")
    print(f"[*] Tasks: {total_tasks}")
    print(f"[*] Workers: {args.workers}")
    print("[!] Use only against systems you are authorized to test.\n")

    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(scan_port, target, port, args.timeout)
            for target in targets
            for port in ports
        ]

        for future in as_completed(futures):
            result = future.result()

            if args.only_open and result.status != "open":
                continue

            results.append(result)

            if result.status == "open":
                print(
                    f"[OPEN] {result.target}:{result.port} "
                    f"service={result.service or '-'} "
                    f"score={result.exposure_score} "
                    f"banner={result.banner[:80] or '-'}"
                )

    results.sort(key=lambda item: (item.target, item.port))

    save_results(results, args.output, output_format)

    open_count = sum(1 for result in results if result.status == "open")

    print()
    print("[+] Scan completed")
    print(f"[+] Open ports: {open_count}")
    print(f"[+] Results saved to: {args.output}")


if __name__ == "__main__":
    main()
