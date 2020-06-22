"""
将变量还原成报文
"""
"""
1.按每个mal的顺序构建全部数据包
2.按每个包的time进行排序
"""
"""
X_mal:
    [][0|1]  [mal包编号][时间点(0)|伪造包个数(1)]
X_craft:
    [][][0|1|2]  [mal包编号][伪造包序号][时间间隔(0)|协议层数(1)|数据长度(2)]       
"""


from scapy.all import *
import random
import string
import numpy as np


def random_bytes(length):
    tmp_str = ''.join(random.choice(string.printable) for _ in range(length))
    return bytes(tmp_str, encoding='utf-8')

def rebuild(
            grp_size,                   # 数据包组中包的个数
            X,
            groupList,
            tmp_pcap_file
           ):

    newList = []  # 存放此粒子表示的包序列

    # 按每个mal的顺序构建全部数据包
    for i in range(grp_size):
        # 遍历当前的mal包的全部cft包
        for j in range(int(round(X.mal[i][1]))):
            pkt = copy.deepcopy(groupList[i])
            if round(X.craft[i][j][1]) == 1:
                if groupList[i].haslayer(Ether):
                    pkt[Ether].remove_payload()
                else:
                    raise RuntimeError("Error in rebuilder!")

            elif round(X.craft[i][j][1]) == 2:
                if groupList[i].haslayer(IP):
                    pkt[IP].remove_payload()
                elif groupList[i].haslayer(IPv6):
                    pkt[IPv6].remove_payload()
                elif groupList[i].haslayer(ARP):
                    pkt[ARP].remove_payload()
                else:
                    raise RuntimeError("Error in rebuilder!")
            elif round(X.craft[i][j][1]) == 3:
                if groupList[i].haslayer(ICMP):
                    pkt[ICMP].remove_payload()
                elif groupList[i].haslayer(TCP):
                    pkt[TCP].remove_payload()
                elif groupList[i].haslayer(UDP):
                    pkt[UDP].remove_payload()
                else:
                    raise RuntimeError("Error in rebuilder!")
            else:
                raise RuntimeError("Error in rebuilder!")
            pkt.add_payload(random_bytes(int(round(X.craft[i][j][2]))))
            pkt.time = X.mal[i][0] - X.craft[i][j][0]
            newList.append(pkt)
        # 将mal也加进来
        mal_pkt = copy.deepcopy(groupList[i])
        mal_pkt.time = X.mal[i][0]
        newList.append(mal_pkt)

    wrpcap(tmp_pcap_file, newList)
    return newList
