#!/usr/bin/env python3

import argparse
import selectors
import socket
import sys
from selectors import EVENT_READ
from selector import make_selector
from typing import NamedTuple, Optional
from udp_scan import scan_udp
from tcp_scan import scan_tcp
from guess import guess_udp, guess_tcp


def parse_specs(specs):
    """
    'tcp/80', 'tcp/12000-12500', 'udp/3000-3100,3200', 'tcp' (без портов = все).
    возвращает список ('TCP' или 'UDP', порт)
    """
    targets = []
    for spec in specs:
        protocol, sep, ports_str = spec.partition("/")
        protocol = protocol.upper()
        if protocol not in ("TCP", "UDP"):
            raise ValueError(f"неизвестный протокол в '{spec}' (ожидается tcp или udp)")

        if not sep:
            ports = range(1, 65536)
        else:
            ports = _parse_ports(ports_str, spec)

        targets.extend((protocol, port) for port in ports)

    return list(dict.fromkeys(targets))


def _parse_ports(text, spec):
    ports = []
    for part in text.split(","):
        lover_str, sep, upper_str = part.partition("-")
        try:
            lover = int(lover_str)
            upper = int(upper_str) if sep else lover
        except ValueError:
            raise ValueError(f"некорректный порт в '{spec}'") from None
        if not 1 <= lover <= upper <= 65535:
            raise ValueError(f"порт вне диапазона 1-65535 в '{spec}'")
        ports.extend(range(lover, upper + 1))
    return ports



class Result(NamedTuple):
    proto: str
    port: int
    ms: Optional[float]
    service: Optional[str]


def print_results(results, verbose, guess):
    for r in results:
        cols = [r.proto, str(r.port)]
        if verbose:
            cols.append(f"{r.ms:.1f}" if r.ms is not None else "-")
        if guess:
            cols.append(r.service or "-")
        print(" ".join(cols))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="Сканер TCP (SYN) и UDP портов",
    )
    parser.add_argument("ip", help="IP-адрес или имя хоста")
    parser.add_argument("specs", nargs="*", metavar="{tcp|udp}[/PORTS]",
                        help="например: tcp/80 tcp/12000-12500 udp/3000-3100,3200")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="таймаут ожидания ответа, с (по умолчанию 2)")
    parser.add_argument("-j", "--num-threads", type=int, default=256,
                        help="максимум проб, ожидающих ответа одновременно (по умолчанию 256)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="колонка времени ответа [TIME,ms] (для TCP)")
    parser.add_argument("-g", "--guess", action="store_true",
                        help="определение протокола прикладного уровня: HTTP, DNS, ECHO")
    return parser


def main(argv=None):
    if not hasattr(selectors, "EpollSelector"):
        print("portscan требует Linux (epoll)", file=sys.stderr)
        return 1

    parser = build_parser()
    args = parser.parse_intermixed_args(argv)

    if not args.specs:
        parser.error("укажите хотя бы одну спецификацию: tcp[/PORTS] или udp[/PORTS]")
    if args.timeout <= 0:
        parser.error("--timeout должен быть больше 0")
    if args.num_threads < 1:
        parser.error("-j должен быть не меньше 1")

    try:
        targets = parse_specs(args.specs)
    except ValueError as e:
        parser.error(str(e))

    try:
        host = socket.gethostbyname(args.ip)
    except socket.gaierror:
        parser.error(f"не удалось разрешить адрес '{args.ip}'")

    tcp_ports = [port for proto, port in targets if proto == "TCP"]
    udp_ports = [port for proto, port in targets if proto == "UDP"]
    window = args.num_threads

    results = []
    try:
        if tcp_ports:
            opened = scan_tcp(host, tcp_ports, args.timeout, window)
            for port, ms in sorted(opened.items()):
                service = guess_tcp(host, port, args.timeout) if args.guess else None
                results.append(Result("TCP", port, ms, service))

        if udp_ports:
            found = scan_udp(host, udp_ports, args.timeout, window)
            for port, reply in sorted(found.items()):
                service = guess_udp(reply) if args.guess else None
                results.append(Result("UDP", port, None, service))
    except PermissionError:
        print("Ошибка: TCP SYN-сканирование требует прав root (sudo)", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Прервано пользователем", file=sys.stderr)
        return 130

    print_results(results, verbose=args.verbose, guess=args.guess)
    return 0


if __name__ == "__main__":
    sys.exit(main())