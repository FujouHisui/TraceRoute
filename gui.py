import time

from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget, QLineEdit, QPushButton, QTextBrowser
from scapy.all import *
from scapy.layers.inet import IP, ICMP

from scapy_icmp_trace import get_network_ip, legit_ip, dns_resolve, pac_send


class Example(QWidget):

    def __init__(self):
        super().__init__()
        self.tb = QTextBrowser(self)
        self.cursor = self.tb.textCursor()
        self.btn = QPushButton('trace', self)
        self.le = QLineEdit(self)

        self.init_ui()  # 界面绘制交给InitUi方法

    def init_ui(self):
        self.le.move(20, 20)
        self.le.setGeometry(20, 20, 400, 30)
        self.le.setPlaceholderText('The IP address or Domain you want to trace')

        self.btn.clicked.connect(self.show_trace)
        self.btn.setGeometry(440, 20, 80, 30)

        self.tb.setGeometry(20, 60, 500, 520)

        self.setGeometry(300, 300, 540, 600)
        self.setWindowTitle('Trace Route')
        self.show()

    def show_trace(self):
        self.le.setEnabled(False)
        self.btn.setEnabled(False)
        self.trace_route(self.le.text())
        self.le.setEnabled(True)
        self.btn.setEnabled(True)

    def closeEvent(self, event):
        sys.exit(app.exec_())

    def get_network_ip(self):
        """get the local network ip, not loopback 127.*"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('1.1.1.1', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def pac_send(self, dst, ttl):
        ip = IP()
        icmp = ICMP()
        my_packet = ip / icmp
        # packet[IP].src = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
        my_packet[IP].src = get_network_ip()
        my_packet[IP].dst = dst
        my_packet[IP].ttl = ttl
        my_packet[ICMP].id = 0x01
        my_packet[ICMP].seq = 0x02
        send_time = time.time()
        p = sr1(my_packet, timeout=2, verbose=False)
        received_time = time.time()
        ping_time = int(round((received_time - send_time) * 1000))

        # p.show()
        if p:
            src_ip = p[IP].src
            return ping_time, src_ip
        else:
            return -1, -1

    def trace_route(self, dst):
        max_ttl = 64
        if not legit_ip(dst):
            try:
                dst = dns_resolve(dst)
            except socket.gaierror:
                self.tb_print("The IP address or Domain is illegal")
                return -1

        self.tb_print("Trace to IP {} up to {} hops.".format(dst, max_ttl))
        ip = "0.0.0.0"
        ttl = 1
        while ttl <= max_ttl and ip != dst:
            j = 0
            delay_time = []
            while j < 3:
                p = pac_send(dst, ttl)
                if p[0] != -1:
                    ip = p[1]
                    delay_time.append(str(p[0]) + "ms")
                else:
                    ip = "Time out"
                    delay_time.append("*")

                j += 1
            self.tb_print(
                '{}\t {:11}\t {:11}\t{:11}\t {:11} '.format(ttl, delay_time[0], delay_time[1], delay_time[2], ip))
            ttl += 1
        return 1

    def dns_resolve(self, domain):
        res = socket.getaddrinfo(domain, None)
        ip = res[0][4][0]
        # tb_print(res)
        return ip

    def legit_ip(self, ip):
        compile_ip = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if compile_ip.match(ip):
            return True
        else:
            return False

    def tb_print(self, mypstr):
        self.tb.append(mypstr)  # 在指定的区域显示提示信息
        self.tb.moveCursor(self.cursor.End)  # 光标移到最后，这样就会自动显示出来
        QtWidgets.QApplication.processEvents()  # 一定加上这个功能，不然有卡顿


if __name__ == "__main__":
    # tb_print(get_network_ip())
    # trace_route("1.1.1.1")
    app = QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())
