from scapy.all import conf, send, sr1
from scapy.layers.inet import IP, TCP


conf.verb = 0 # отключение вывода в консоль


def syn_scan(host, port, timeout = 1.0):

  packet = IP(dst=host) / TCP(dport=port, flags="S") # ip заголовок + tcp заголовок с флагом syn

  response = sr1(packet, timeout=timeout) # отправляем пакет и ждем первый ответный

  if response is None:
    return "FILTERED (нет ответа)"

  if response.haslayer(TCP):
    flags = response.getlayer(TCP).flags

    if flags == 0x12: # syn + ack
      rst_packet = IP(dst=host) / TCP(dport=port, flags="R") # сброс полуоткрытого соединения, rst
      send(rst_packet)
      return "OPEN"

    elif flags == 0x14 or flags == 0x04: # rst + ack - порт закрыт
      return "CLOSED"

  return "FILTERED (ICMP ошибка)"