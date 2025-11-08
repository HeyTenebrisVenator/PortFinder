#!/usr/bin/env python3
"""
Port scanner + simple banner grabber com pool de workers.
- Permite escanear um único domínio/IP ou uma lista em um arquivo (.txt) (uma entrada por linha).
- Permite escolher portas (lista, intervalo ou padrão).
- Grava saída em CSV ou TXT. TXT usa formato: <host> : <porta> : <serviço/banner>
- Use apenas em hosts que você tem permissão para escanear!
"""

import socket
import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple
import sys
import threading

LOCK = threading.Lock()

HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"
SMTP_PROBE = b"HELO example.com\r\n"
TELNET_PROBE = b"\r\n"
PORT_PROBES = {
    80: HTTP_PROBE,
    8080: HTTP_PROBE,
    8000: HTTP_PROBE,
    443: HTTP_PROBE,
    25: SMTP_PROBE,
    23: TELNET_PROBE,
    21: b"\r\n",
}

def parse_ports(port_string: str) -> List[int]:
    """
    Recebe uma string como:
    "22,80,443"  -> [22,80,443]
    "1-1024"     -> [1,...,1024]
    "22,80,1000-1010"
    """
    parts = port_string.split(',')
    ports = set()
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if '-' in p:
            a, b = p.split('-', 1)
            a = int(a.strip()); b = int(b.strip())
            if a > b:
                a, b = b, a
            for x in range(max(1, a), min(65535, b) + 1):
                ports.add(x)
        else:
            ports.add(int(p))
    return sorted(ports)

def load_targets_from_file(path: str) -> List[str]:
    with open(path, 'r', encoding='utf-8') as f:
        targets = [line.strip() for line in f if line.strip()]
    return targets

def get_service_by_port(port: int) -> str:
    try:
        return socket.getservbyport(port, 'tcp')
    except Exception:
        return ""

def banner_grab_connected(s: socket.socket, port: int, timeout: float = 2.0) -> str:
    """
    Tenta receber dados passivos. Se nada for recebido e conhecermos um probe
    para a porta, envia um probe simples e tenta receber resposta.
    """
    s.settimeout(timeout)
    banner = b""
    try:
        try:
            banner = s.recv(1024)
        except socket.timeout:
            banner = b""

        if not banner:
            probe = PORT_PROBES.get(port)
            if probe:
                try:
                    s.sendall(probe)
                    banner = s.recv(2048)
                except Exception:
                    banner = b""
    except Exception:
        banner = b""

    try:
        text = banner.decode('utf-8', errors='replace').strip()
    except Exception:
        text = repr(banner)
    return text if text else ""

def scan_port(host: str, port: int, timeout: float = 1.5) -> Tuple[str, int, bool, str]:
    """
    Tenta conectar ao host:port. Retorna (host, port, is_open, banner_or_service)
    """
    try:
        addr_info = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        family, socktype, proto, canonname, sockaddr = addr_info[0]
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect(sockaddr)
            except Exception:
                return (host, port, False, "")
            banner = banner_grab_connected(s, port, timeout=timeout)
            if not banner:
                service = get_service_by_port(port)
                return (host, port, True, service or "")
            else:
                return (host, port, True, banner)
    except Exception as e:
        return (host, port, False, "")

def write_csv_row(csv_writer, row):
    with LOCK:
        csv_writer.writerow(row)

def append_txt_line(path: str, line: str):
    with LOCK:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')

def main():
    parser = argparse.ArgumentParser(description="Scanner de portas simples com banner grabbing.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--target', '-t', help='Domínio ou IP único a ser escaneado (ex: example.com)')
    group.add_argument('--file', '-f', help='Arquivo .txt com uma entrada por linha (domínio ou IP)')
    parser.add_argument('--ports', '-p', required=True,
                        help='Portas: lista ou intervalos. Ex: "22,80,443" ou "1-1024" ou "22,80,1000-1010"')
    parser.add_argument('--workers', '-w', type=int, default=100, help='Número de threads no pool (padrão 100)')
    parser.add_argument('--timeout', type=float, default=1.5, help='Timeout de conexão em segundos (padrão 1.5)')
    parser.add_argument('--out', '-o', default='results.csv', help='Arquivo de saída (.csv ou .txt).')
    parser.add_argument('--format', choices=['csv', 'txt'], default=None,
                        help='Força formato de saída. Se omitido, inferido pela extensão do --out')
    args = parser.parse_args()

    out_path = args.out
    out_format = args.format
    if not out_format:
        if out_path.lower().endswith('.csv'):
            out_format = 'csv'
        elif out_path.lower().endswith('.txt'):
            out_format = 'txt'
        else:
            out_format = 'csv'

    if args.target:
        targets = [args.target.strip()]
    else:
        targets = load_targets_from_file(args.file)

    ports = parse_ports(args.ports)
    if not ports:
        print("Nenhuma porta válida fornecida.", file=sys.stderr)
        sys.exit(1)

    total_tasks = len(targets) * len(ports)
    print(f"Alvo(s): {len(targets)} | Portas: {len(ports)} | Tarefas: {total_tasks} | Workers: {args.workers}")
    print("ESCANEAMENTO INICIANDO — tenha certeza de ter permissão para escanear os alvos.\n")

    if out_format == 'csv':
        csvfile = open(out_path, 'w', newline='', encoding='utf-8')
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['target', 'port', 'open', 'service_or_banner'])
    else:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('')

        csvfile = None
        csv_writer = None

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = []
            for host in targets:
                for port in ports:
                    futures.append(executor.submit(scan_port, host, port, args.timeout))

            done = 0
            for fut in as_completed(futures):
                done += 1
                try:
                    host, port, is_open, svc = fut.result()
                except Exception as e:
                    continue

                if is_open:
                    service_guess = svc if svc else get_service_by_port(port)
                    if out_format == 'csv':
                        write_csv_row(csv_writer, [host, port, 'open', service_guess])
                    else:
                        line = f"{host} : {port} : {service_guess}"
                        append_txt_line(out_path, line)

                    print(f"[OPEN] {host}:{port} -> {service_guess}")
                else:
                    print(f"[closed] {host}:{port}", end='\r')

            print("\nEscaneamento concluído.")
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário.")
    finally:
        if csvfile:
            csvfile.close()

if __name__ == '__main__':
    main()
