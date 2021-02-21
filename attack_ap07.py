#import re
from time import sleep
import binascii
import random, string
from scapy.all import *

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス
sample_string='0123456789abcdef0123456789abcdef'

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
TH1 = 71 #WriteProperty:71

IF = "lo0"
#FILTER = "ether src "+ T_MAC1 +" and not ether src "+ M_MAC

eth = Ether()
eth.src = 'b8:27:eb:3c:2e:c9'
eth.dst = 'ff:ff:ff:ff:ff:ff'
eth.type = 1

ip = IP()
ip.version =4
ip.tos = 0x0
ip.ihl = 5
ip.id = 55
ip.flags = 0x001
ip.frag = 0
ip.ttl = 64
ip.proto = 'tcp'
ip.src = '192.168.100.11'
ip.dst = '192.168.1.10'

tcp = TCP()
tcp.sport = 80
tcp.dport = 55555# bacnet
tcp.dataofs = 0x101
tcp.flags='E'
tcp.urgptr=0 #0x20
tcp.seq=100
tcp.options=[("MSS",1460)]

raw = Raw()

pkt = eth


for i in range(0,50):
    sendp(pkt,iface=IF)
    

