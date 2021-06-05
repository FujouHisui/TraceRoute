from scapy.all import *
from scapy.layers.inet import IP, ICMP
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QGridLayout, QTextEdit, QPushButton, QInputDialog, \
    QTextBrowser
from PyQt5.QtGui import QIcon


def get_network_ip():
    """get the local network ip, not loopback 127.*"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('1.1.1.1', 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def pac_send(dst, ttl):
    ip = IP()
    icmp = ICMP()
    my_packet = ip / icmp
    # packet[IP].src = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
    my_packet[IP].src = get_network_ip()
    my_packet[IP].dst = dst
    my_packet[IP].ttl = ttl
    my_packet[ICMP].type = 0x08
    my_packet[ICMP].id = 0x01
    my_packet[ICMP].seq = 0x02
    send_time = time.time()
    p = sr1(my_packet, timeout=2, verbose=False)
    ping_time = int((time.time() - send_time) * 1000)
    p.show()
    if p:
        src_ip = p[IP].src
        return ping_time, src_ip
    else:
        return -1, -1


def trace_route(dst):
    max_ttl = 64
    if not legit_ip(dst):
        try:
            dst = dns_resolve(dst)
        except socket.gaierror:
            sys.exit("The IP address or Domain is illegal")

    print("Trace to IP {} up to {} hops.".format(dst, max_ttl))
    ip = "0.0.0.0"
    ttl = 1
    while ttl <= max_ttl and ip != dst:
        j = 0
        delay_time = []
        print('{:2}\t'.format(ttl), end='')
        while j < 3:
            p = pac_send(dst, ttl)
            if p[0] != -1:
                ip = p[1]
                delay_time.append(str(p[0]) + "ms")
            else:
                ip = "Time out"
                delay_time.append("*")
            print('{:11}'.format(delay_time[j]), end='')
            j += 1
        print('{:11}'.format(ip))
        ttl += 1
    return 1


def dns_resolve(domain):
    res = socket.getaddrinfo(domain, None)
    ip = res[0][4][0]
    # print(res)
    return ip


def legit_ip(ip):
    compile_ip = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if compile_ip.match(ip):
        return True
    else:
        return False


if __name__ == "__main__":
    # print(get_network_ip())
     #trace_route("1.1.1.1")
     pac_send("1.1.1.1",1)

