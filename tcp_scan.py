import random
import time

from scapy.all import conf
from scapy.layers.inet import IP, TCP
from selectors import EVENT_READ
from selector import make_selector


conf.verb = 0 # отключение вывода в консоль


SYN_ACK = 0x12
RST_FLAG = 0x04
MASK32 = 0xFFFFFFFF
MSS = 1460


def scan_tcp(host, ports, timeout, window):
    """ возвращает словарь: открытый порт -> время ответа в мс.
    window: максимум syn ожидающих ответа одновременно. """
    sport = random.randint(40000, 60000)  # исходный порт

    sock = conf.L3socket()  # многоразовый сокет
    sel = make_selector()
    sel.register(sock.fileno(), EVENT_READ) # регистрируем файловый дескриптор для сокета в селекторе, чтобы реагировать на пакеты

    seqs = {} # port -> seq (номер первого байта отправленного пакета) нашего SYN
    pending = {} # port -> момент отправки syn, очередь активных проверок без ответа
    opened = {} # port -> время ответа, мс итоговый рез

    def del_old_port(now):
        """удаление старых портов по таймауту"""
        while pending:
            port = next(iter(pending))
            if now - pending[port] < timeout:
                break
            del pending[port]

    def handle_packet(packet):
        """ разбор пойманного пакета"""
        ip = packet.getlayer(IP)
        tcp = packet.getlayer(TCP)
        if ip is None or tcp is None or ip.src != host or tcp.dport != sport:
            return # левый пакет

        port = tcp.sport
        if port not in seqs or tcp.ack != ((seqs[port] + 1) & MASK32):
            return  # ответ не на наш SYN

        flags = int(tcp.flags)
        if (flags & SYN_ACK) == SYN_ACK: # syn+ack
            # закрываем полуоткрытое соединение флагом сброса rst
            sock.send(IP(dst=host) / TCP(sport=sport, dport=port, flags="R", seq=tcp.ack))
            t_sent = pending.pop(port, None)
            if t_sent is not None:
                opened[port] = (time.monotonic() - t_sent) * 1000
        elif flags & RST_FLAG:
            pending.pop(port, None)

    def poll():
        now = time.monotonic()
        del_old_port(now)
        if not pending:
            return
        oldest = next(iter(pending.values()))
        if sel.select(max(0.0, oldest + timeout - now)):# ждем событие до смерти старейшего
            packet = sock.recv()
            if packet is not None:
                handle_packet(packet)
        del_old_port(time.monotonic())

    try:
        for port in ports:
            while len(pending) >= window: # нельзя отправить новый syn пока ожидаемая очередь пакетов больше окна
                poll()
            seq = random.getrandbits(32)
            seqs[port] = seq
            pending[port] = time.monotonic()
            sock.send(IP(dst=host) / TCP(sport=sport, dport=port, flags="S",
                seq=seq, options=[("MSS", MSS)]))
        while pending:
            poll()
    finally:
        sel.close()
        sock.close()

    return opened