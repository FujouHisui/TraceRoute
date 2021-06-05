import IP2Location
import ipdb
from PyQt5 import QtWidgets
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtWidgets import QApplication, QLineEdit, QPushButton, QTextBrowser, QMainWindow
from scapy.all import *
from scapy.layers.inet import IP, ICMP

from scapy_icmp_trace import get_network_ip, legit_ip, dns_resolve, pac_send

# Must run in root user!!!

db = ipdb.District("ipipfree.ipdb")
IP2LocObj = IP2Location.IP2Location()
IP2LocObj.open("IP2LOCATION-LITE-DB9.BIN")


class icmp_trace_route(QMainWindow):

    def __init__(self):
        super().__init__()
        self.tb = QTextBrowser(self)
        self.cursor = self.tb.textCursor()
        self.btn = QPushButton('trace', self)
        self.le = QLineEdit(self)
        self.browser = QWebEngineView()
        self.init_ui()  # 界面绘制交给InitUi方法


    def init_ui(self):
        self.le.move(20, 20)
        self.le.setGeometry(20, 20, 560, 30)
        self.le.setPlaceholderText('The IP address or Domain you want to trace')

        self.btn.clicked.connect(self.show_trace)
        self.btn.setGeometry(600, 20, 80, 30)

        self.tb.setGeometry(20, 60, 660, 600)
        # self.tb.setGeometry(20, 60, 660, 300)

        self.browser.setGeometry(20, 400, 660, 300)

        self.setGeometry(300, 300, 700, 700)
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
        my_packet[ICMP].type = 0x08
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
        self.tb.clear()
        if not legit_ip(dst):
            try:
                dst = dns_resolve(dst)
            except socket.gaierror:
                self.tb_print("The IP address or Domain is illegal")
                return -1
        self.tb_print("Trace to IP {} up to {} hops.".format(dst, max_ttl))
        ip = "Time out"
        ip_lat = []
        ip_lng = []
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
                    delay_time.append("*")
                j += 1
            if (ip != "Time out"):
                # if (db.find(ip, "CN")[0] != db.find(ip, "CN")[1]):
                #    ip_pos = db.find(ip, "CN")[0] + "," + db.find(ip, "CN")[1]
                # else:
                #    ip_pos = db.find(ip, "CN")[1]

                rec = IP2LocObj.get_all(ip)
                ip_pos = rec.country_short + "," + rec.region + "," + rec.city
                ip_lat.append(rec.latitude)
                ip_lng.append(rec.longitude)
            else:
                ip_pos = ""
                ip_lat.append("")
                ip_lng.append("")
            self.tb_print(
                '{}\t{:6}\t{:6}\t{:6}\t{:24}\t{}'.format(
                    ttl, delay_time[0], delay_time[1], delay_time[2], ip, ip_pos))
            ttl += 1
        self.tb_print("Trace finished\n可视化地图已保存为map.html")
        self.map_show(self.loc_data(ip_lat, ip_lng))

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
        self.tb.moveCursor(self.cursor.End)  # 光标移到最后
        QtWidgets.QApplication.processEvents()

    def map_show(self, data):
        map_html = ('''
        <!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
    <style type="text/css">
    body, html,#allmap {width: 100%;height: 100%;overflow: hidden;margin:0;font-family:"微软雅黑";}
    </style>
    <script type="text/javascript" src="http://api.map.baidu.com/api?v=2.0& ak=Q3iR0AoetHIiYOGBY5cfCITfuPsHgRNz"></script>
    <title>折线上添加方向箭头</title>
</head>
<body>
    <div id="allmap"></div>
</body>
</html>
<script type="text/javascript">
    // 百度地图API功能
    var map = new BMap.Map("allmap");    // 创建Map实例
    map.centerAndZoom(new BMap.Point(116.404, 39.915), 6);  // 初始化地图,设置中心点坐标和地图级别   
    map.enableScrollWheelZoom(true);     //开启鼠标滚轮缩放
  var sy = new BMap.Symbol(BMap_Symbol_SHAPE_BACKWARD_OPEN_ARROW, {
    scale: 0.6,//图标缩放大小
    strokeColor:'#fff',//设置矢量图标的线填充颜色
    strokeWeight: '2',//设置线宽
});
var icons = new BMap.IconSequence(sy, '10', '30');
// 创建polyline对象
var pois = [
        ''' + data + '''
        ];
var polyline =new BMap.Polyline(pois, {
   enableEditing: false,//是否启用线编辑，默认为false
   enableClicking: true,//是否响应点击事件，默认为true
   icons:[icons],
   strokeWeight:'4',//折线的宽度，以像素为单位
   strokeOpacity: 0.8,//折线的透明度，取值范围0 - 1
   strokeColor:"#FF0000" //折线颜色
});

map.addOverlay(polyline);          //增加折线
  
  
</script>
        ''')
        with open("map.html", "w") as file:
            file.write(map_html)
        #self.browser.setHtml(map_html)
        return

    def loc_data(self, latitude, longitude):
        data = ""
        for i in range(0, len(latitude)):
            if latitude[i] != "" and (latitude[i] != 0.0 and longitude[i] != 0.0):
                if i < len(latitude)-1:
                    data += "new BMap.Point({},{}),".format(longitude[i], latitude[i])
                elif i == len(latitude)-1:
                    data += "new BMap.Point({},{})".format(longitude[i], latitude[i])
        return data


if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = icmp_trace_route()
    sys.exit(app.exec_())
