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
eth.dst = 'e8:98:6d:bb:cc:01'
eth.type = 2048

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
raw.load = "30373930eb80db6180f784b2a3c8289c25fc2f47d86a83a113d10c8c19eff750418996e10a59ea7456b18d3118c6096114a80edfe58d5f1373f449486097a6ffdd437d9247fb9cb7f0334a3262c45a9d74004def9852f679b3b8c2c0926705a0eed6ab74dcbf7130b736c43496c0fd65bf50cb8f63eda4af2721d5d17786431d9dfd06b9ea36aa3d2d3dd8397ec9b2973ef1c74e949301041c13fbf2bc44ce6168aa5d2387251c200b2be022aedb2d742db3decd7a6e4a526877a7b52bc1d4988204ea175d02701a450790150efe12b20537edcaa794dcfe8ebf1f3a04cbe16b5959847ee94ca86ed75f707a4eb46d3e5e3f8bc51c61f1a7482e6e245adf8a8ce5e358ad81d11886f0eeb0a4ce209227fc2f47da6b8bab15d30c8c18e6f75d428896e10b50ea7954b38d3119cf096c16aa0edfe4845f1e72f74948619ea6f2dc407d9246f29cbaf0374a3263cd5a9074044def995bf674bcbdc2c0936e05ade1d3ab74ddb6713db930c43497c9fd68b157cb8f62e4a4a12026d5d1768f43139af506b9eb3faa332b35d8397fc0b2993bf8c74e959a010a191afbf2bd4cc6676aa85d23862d14260929e022afd3257228b1decd7b6642546d75a7b52ac9dc9e8606ea175c0a781c410590150ff61ab40235edcaa69cd4f889bd1f3a05c3e96d5f5b847ee844a068d15d707a4fbc6538573d8bc51d69f9a1402c6e245bd782"

pkt = eth/ip/tcp/raw

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
    #array[0] = str(random.randint(0,255))
    #array[1] = str(random.randint(0,255))
    #array[2] = str(random.randint(0,255))
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
    pkt[IP].proto = random.randint(0,63)
    pkt[IP].id = random.randint(0,20000)
    pkt[IP].frag += 800
    pkt[TCP].dport = random.randint(0,60000)
    pkt[TCP].dataofs = random.randint(0,8)
    pkt[TCP].reserved = random.randint(0,4)
    pkt[TCP].seq +=1
    pkt[TCP].window = random.randint(0,8192)
    
    #pkt = eth/ip/tcp/on_01

