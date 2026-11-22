import socket
import struct

DNS_QUERY = (struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # флаг RD
             + b"\x07example\x03com\x00"
             + struct.pack(">HH", 1, 1))                          # A, IN
HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


def guess_udp(reply):
    if _is_dns_reply(reply):
        return "DNS"
    if reply == DNS_QUERY:
        return "ECHO"
    return None


def guess_tcp(host, port, timeout):
    if port == 53: # обычно днс на этом порту
        checks = [_check_dns_tcp, _check_http_or_echo]
    else:
        checks = [_check_http_or_echo, _check_dns_tcp]
    for check in checks:
        proto = check(host, port, timeout)
        if proto:
            return proto
    return None


def _is_dns_reply(data):
    """ ответ dns если совпадает ID и установлен бит ответа"""
    return len(data) >= 12 and data[:2] == DNS_QUERY[:2] and bool(data[2] & 0x80)


def _recv_exactly(sock, n):
    buf = b""
    try:
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    return buf


def _check_http_or_echo(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(HTTP_PROBE)
            reply = _recv_exactly(s, len(HTTP_PROBE))
    except OSError:
        return None
    if reply.startswith(b"HTTP/"):
        return "HTTP"
    if reply == HTTP_PROBE:
        return "ECHO"
    return None


def _check_dns_tcp(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(DNS_QUERY)) + DNS_QUERY)  # DNS over TCP: префикс длины
            header = _recv_exactly(s, 2)
            if len(header) < 2:
                return None
            body = _recv_exactly(s, struct.unpack(">H", header)[0])
    except OSError:
        return None
    return "DNS" if _is_dns_reply(body) else None