#import re
from time import sleep
import binascii
import random, string
from scapy.all import *

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
TH1 = 71 #WriteProperty:71
SLEEP_TIME = 1

IF = "en8"
#FILTER = "ether src "+ T_MAC1 +" and not ether src "+ M_MAC

ON01 ='810a00190104000479100c0100006d1e09552e91012f39081f'
ON02 ='810a001901040004ee100c010000751e09552e91012f39081f'
AL01 ='810b00250100100209001c0100006d2c00c0000039004e09552e91012f096f2e8204802f4f'
AL02 ='810b00250100100209001c010000752c00c0000039004e09552e91012f096f2e8204802f4f'

on_01 = binascii.unhexlify(AL01)
on_02 = binascii.unhexlify(AL02)


eth = Ether()
eth.src = '74:3a:65:84:c7:82'
eth.dst = '00:e0:5d:00:32:96'
eth.type = 0x0800

ip = IP()
ip.version =4
ip.ihl = 5
ip.id = 1
ip.flags = 0x0000
ip.ttl = 64
ip.proto = 'udp'
ip.src = '192.168.10.10'
ip.dst = '192.168.10.30'

udp = UDP()
udp.sport = 47808
udp.dport = 47808 # bacnet

for i in range(0,2):
    ip.id += 2
    pkt = eth/ip/udp/on_01
    sendp(pkt,iface=IF)
    sleep(SLEEP_TIME)
    ip.id += 2
    pkt = eth/ip/udp/on_02
    sendp(pkt,iface=IF)
    sleep(SLEEP_TIME)

