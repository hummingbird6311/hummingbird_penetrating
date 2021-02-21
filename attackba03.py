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

ON01 ='810a00190104000490100c010000281e09552e91012f39081f'
ON02 ='810a00190104000489100c010000001e09552e91012f39081f'
ON03 ='810a00190104000491100c010000101e09552e91012f39081f'
ON04 ='810a00190104000499100c010000081e09552e91012f39081f'
OF01 ='810a00190104000494100c010000281e09552e91002f39081f'
OF02 ='810a0019010400048d100c010000001e09552e91002f39081f'
OF03 ='810a00190104000495100c010000101e09552e91002f39081f'
OF04 ='810a0019010400049a100c010000081e09552e91002f39081f'

on_01 = binascii.unhexlify(ON01)
on_02 = binascii.unhexlify(ON02)
on_03 = binascii.unhexlify(ON03)
on_04 = binascii.unhexlify(ON04)
of_01 = binascii.unhexlify(OF01)
of_02 = binascii.unhexlify(OF02)
of_03 = binascii.unhexlify(OF03)
of_04 = binascii.unhexlify(OF04)

eth = Ether()
eth.src = '74:3a:65:84:c7:82'
eth.dst = '00:e0:5d:00:36:ef'
eth.type = 0x0800

ip = IP()
ip.version =4
ip.ihl = 5
ip.id = 1
ip.flags = 0x0000
ip.ttl = 64
ip.proto = 'udp'
ip.src = '192.168.10.10'
ip.dst = '192.168.10.12'

udp = UDP()
udp.sport = 47808
udp.dport = 47808 # bacnet

for i in range(0,10):
    ip.id += 2
    pkt = eth/ip/udp/on_01
    sendp(pkt,iface=IF)
    sleep(1)
    ip.id += 2
    pkt = eth/ip/udp/on_02
    sendp(pkt,iface=IF)
    sleep(1)
    ip.id += 2
    pkt = eth/ip/udp/on_03
    sendp(pkt,iface=IF)
    sleep(1)
    ip.id += 2
    pkt = eth/ip/udp/on_04
    sendp(pkt,iface=IF)
    sleep(1)
    ip.id += 2
    pkt = eth/ip/udp/of_01
    sendp(pkt,iface=IF)
    sleep(1)
    ip.id += 2
    pkt = eth/ip/udp/of_02
    sendp(pkt,iface=IF)
    sleep(1)
    ip.id += 2
    pkt = eth/ip/udp/of_03
    sendp(pkt,iface=IF)
    sleep(1)
    ip.id += 2
    pkt = eth/ip/udp/of_04
    sendp(pkt,iface=IF)
    sleep(1)

