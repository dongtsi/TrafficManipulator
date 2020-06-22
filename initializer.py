"""
                                 ics_time                       
      |-----------------|+++++++++++++++++++++++|
last_end_time     groupList[-1].time      last_end_time(*) 
                                          cur_end_time
"""
# begin_timestamp = 1540450873.452971

from scapy.all import *
import random
import numpy as np
from utils import Unit


def decide_has_pkt(crafted_pkt_prob):
    r = random.random()
    if r < crafted_pkt_prob:
        return True
    else:
        return False


def initialize(
                grp_size,                   # 数据包组中包的个数
                last_end_time,              # 上一个数据包组最后一个包的时间
                groupList,                  # 当前数据包组的原始pcap信息
                max_time_extend,            # 最大允许拉伸的时间间隔倍数
                max_cft_pkt,                # 最多允许一个mal包携带多少个cft包
                min_time_extend,
                max_crafted_pkt_prob,
               ):

    X = Unit(grp_size,max_cft_pkt)  # 建立粒子的位置变量

    # 随机拉伸原始数据包
    ics_time = 0                # 累计增加的时间

    for i in range(grp_size):
        if i == 0:
            itv = groupList[i].time - last_end_time
        else:
            itv = groupList[i].time - groupList[i-1].time
        # ics_time += random.uniform(0,max_time_extend)*itv
        ics_time += random.uniform(min_time_extend,max_time_extend)*itv
        X.mal[i][0] = groupList[i].time + ics_time

    # 计算最大允许的序列全部经过时间
    max_mal_itv = (groupList[-1].time - last_end_time) * (max_time_extend + 1)

    # 建立slot map
    slot_num = grp_size * max_cft_pkt   # 槽位数
    slot_itv = max_mal_itv/slot_num  # 槽位之间的时间间隔

    # 创建cft包
    crafted_pkt_prob = random.uniform(0, max_crafted_pkt_prob)  # 伪造包生成概率
    nxt_mal_no = 0  # 记录当前的slot服务的mal包的在组中的序号

    proto_max_lmt = []  # 协议层数`的最大值（每个mal包不同）,需要initializer计算并返回给particle
    # 计算proto_max_lmt
    for i in range(grp_size):
        if groupList[i].haslayer(TCP) or groupList[i].haslayer(UDP) or groupList[i].haslayer(ICMP):
            proto_max_lmt.append(3.)
        elif groupList[i].haslayer(IP) or groupList[i].haslayer(IPv6) or groupList[i].haslayer(ARP):
            proto_max_lmt.append(2.)
        elif groupList[i].haslayer(Ether):
            proto_max_lmt.append(1.)
        else:
            proto_max_lmt.append(0.)
            
    for i in range(slot_num):
        slot_time = i * slot_itv + last_end_time
        if slot_time >= X.mal[nxt_mal_no][0]:
            nxt_mal_no += 1
            if nxt_mal_no == grp_size: # 遇到最后一个mal包后不再需要加craft包
                break
        if (not decide_has_pkt(crafted_pkt_prob)) or X.mal[nxt_mal_no][1] == max_cft_pkt:
            continue
        cft_no = int(round(X.mal[nxt_mal_no][1]))  # 新增的craft包的下标

        if proto_max_lmt[nxt_mal_no] == 3.:
            X.craft[nxt_mal_no][cft_no][1] = random.choice([1.,2.,3.])
            mtu = 1460
        elif proto_max_lmt[nxt_mal_no] == 2.:
            X.craft[nxt_mal_no][cft_no][1] = random.choice([1., 2.])
            mtu = 1480
        elif proto_max_lmt[nxt_mal_no] == 1.:
            X.craft[nxt_mal_no][cft_no][1] = 1.
            mtu = 1500
        else:   # 如果没有Ether,则没有伪造包
            continue

        X.craft[nxt_mal_no][cft_no][0] = X.mal[nxt_mal_no][0] - slot_time
        X.craft[nxt_mal_no][cft_no][2] = random.uniform(0, mtu)

        X.mal[nxt_mal_no][1] += 1. # 增加了1个craft包

    return X,proto_max_lmt

