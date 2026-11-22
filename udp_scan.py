import socket


def scan_udp_port(host, port, payload, timeout = 1.0):
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(timeout)
    try:
      sock.sendto(payload, (host, port))
      sock.recvfrom(1024)
      return "OPEN"
    except socket.timeout:
      return "OPEN|FILTERED"
    except ConnectionResetError:
      return "CLOSED"
