import socket
import time

from selector import make_selector
from guess import DNS_QUERY
from selectors import EVENT_READ


def scan_udp(host, ports, timeout, window):
    """ возвращает: открытый порт -> полученный ответ."""
    sel = make_selector()
    pending = {} # port -> (socket, время отправки)
    found = {} # port -> ответ

    def close_socket(port):
        s, _ = pending.pop(port)
        sel.unregister(s)
        s.close()

    def del_old_port(now):
        while pending:
            port = next(iter(pending))
            if now - pending[port][1] < timeout:
                break
            close_socket(port)

    def poll():
        now = time.monotonic()
        del_old_port(now)
        if not pending:
            return
        oldest = next(iter(pending.values()))[1]
        for key, _ in sel.select(max(0.0, oldest + timeout - now)): # ждем событие хотя бы на одном из сокетов до смерти старейшего
            port = key.data
            try:
                found[port] = key.fileobj.recv(4096)
            except OSError:
                pass  # порт закрыт
            close_socket(port)
        del_old_port(time.monotonic())

    try:
        for port in ports:
            while len(pending) >= window:
                poll()

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setblocking(False)
            try:
                s.connect((host, port))
                s.send(DNS_QUERY)
            except OSError:
                s.close()
                return
            sel.register(s, EVENT_READ, port)
            pending[port] = (s, time.monotonic())

        while pending:
            poll()
    finally:
        for port in list(pending):
            close_socket(port)
        sel.close()

    return found
