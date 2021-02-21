#import re
#from time import sleep
import binascii
import random, string
from scapy.all import *

DST_IP1 = '172.16.128.153'
DST_IP2 = '192.168.6.13'
DST_IP3 = '192.168.6.16'

T_MAC1 = 'e8:e0:b7:a9:8b:c7'#172.16.128.153
T_MAC2 = '00:40:1a:1e:58:4a'#192.168.6.13
M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス

IF = "en8"
FILTER = "ip and udp and not src port 55555"

TH1 = 180
CH_POS = 215

sample_string='0123456789abcdef0123456789abcdef'
sample_string2='01234567890123456789'
mini_string='012012012012012'

def relay_process(pkt):
    print("roop\n")
    tmp1 = pkt[Ether].src
    array = tmp1.split(':')
    for i in range(5):
        array[i]==''.join([random.choice(sample_string) for n in range(2)])
    tmp1 = ':'.join(array)
    #pkt[Ether].src = tmp
    tmp2 = pkt[IP].src
    array2 = tmp2.split('.')
    #for i in range(2:4):
    #array2[0]=str(random.randint(0,255))
    #array2[1]=str(random.randint(0,255))
    #array2[2]=str(random.randint(0,255))
    array2[3]=str(random.randint(0,255))
    tmp2 = '.'.join(array2)
    #ary3 = [array2[0],array2[2],array2[1],array2[3]]
    #ary4 = [array2[0],array2[3],array2[1],array2[2]]
    #ary5 = [array2[0],array2[1],array2[3],array2[2]]
    #tmp3 = '.'.join(ary3)
    #tmp4 = '.'.join(ary4)
    #tmp5 = '.'.join(ary5)
   #pkt[IP].src = tmp
    #pkt[IP].dst = DST_IP1
    #print(tmp3)
    eth = Ether(src=tmp1)
    ip=IP(src=tmp2,dst=pkt[IP].src)  
    SYN=TCP(sport=55555,dport=pkt[IP].dport,flags="S",seq=12345)
    frame = eth/ip/SYN
    sendp(frame,iface=IF)
    
    #ip=IP(src=tmp3,dst=pkt[IP].src)
    #frame= eth/ip/SYN
    #sendp(frame,iface=IF)
    #ip=IP(src=tmp4,dst=pkt[IP].src)
    #frame= eth/ip/SYN
    #sendp(frame,iface=IF)
    #ip=IP(src=tmp5,dst=pkt[IP].src)
    #frame= eth/ip/SYN
    #sendp(frame,iface=IF)

sniff(iface=IF, prn=relay_process, filter=FILTER, store=0)


