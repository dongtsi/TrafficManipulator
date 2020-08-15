"""
                                 ics_time                       
      |-----------------|+++++++++++++++++++++++|
last_end_time     groupList[-1].time      last_end_time(*) 
                                          cur_end_time
"""

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
    grp_size,  # Number of pkts in each group
    last_end_time,
    groupList,  # Pcap info in current group
    max_time_extend,  # maximum time overhead (l_t)
    max_cft_pkt,  # maximum crafted traffic overhead (l_c)
    min_time_extend,
    max_crafted_pkt_prob,
):

    X = Unit(grp_size, max_cft_pkt)  # position vector

    ics_time = 0  # accumulated increased ITA

    for i in range(grp_size):
        if i == 0:
            itv = groupList[i].time - last_end_time
        else:
            itv = groupList[i].time - groupList[i - 1].time
        # ics_time += random.uniform(0,max_time_extend)*itv
        ics_time += random.uniform(min_time_extend, max_time_extend) * itv
        X.mal[i][0] = groupList[i].time + ics_time

    max_mal_itv = (groupList[-1].time - last_end_time) * (max_time_extend + 1)

    # building slot map
    slot_num = grp_size * max_cft_pkt
    slot_itv = max_mal_itv / slot_num

    # initializing crafted pkts
    crafted_pkt_prob = random.uniform(0, max_crafted_pkt_prob)
    nxt_mal_no = 0

    proto_max_lmt = []  # maximum protocol layer number
    for i in range(grp_size):
        if groupList[i].haslayer(TCP) or groupList[i].haslayer(
                UDP) or groupList[i].haslayer(ICMP):
            proto_max_lmt.append(3.)
        elif groupList[i].haslayer(IP) or groupList[i].haslayer(
                IPv6) or groupList[i].haslayer(ARP):
            proto_max_lmt.append(2.)
        elif groupList[i].haslayer(Ether):
            proto_max_lmt.append(1.)
        else:
            proto_max_lmt.append(0.)

    for i in range(slot_num):
        slot_time = i * slot_itv + last_end_time
        if slot_time >= X.mal[nxt_mal_no][0]:
            nxt_mal_no += 1
            if nxt_mal_no == grp_size:
                break
        if (not decide_has_pkt(crafted_pkt_prob)
            ) or X.mal[nxt_mal_no][1] == max_cft_pkt:
            continue
        cft_no = int(round(X.mal[nxt_mal_no][1]))

        if proto_max_lmt[nxt_mal_no] == 3.:
            X.craft[nxt_mal_no][cft_no][1] = random.choice([1., 2., 3.])
            mtu = 1460
        elif proto_max_lmt[nxt_mal_no] == 2.:
            X.craft[nxt_mal_no][cft_no][1] = random.choice([1., 2.])
            mtu = 1480
        elif proto_max_lmt[nxt_mal_no] == 1.:
            X.craft[nxt_mal_no][cft_no][1] = 1.
            mtu = 1500
        else:
            continue

        X.craft[nxt_mal_no][cft_no][0] = X.mal[nxt_mal_no][0] - slot_time
        X.craft[nxt_mal_no][cft_no][2] = random.uniform(0, mtu)

        X.mal[nxt_mal_no][1] += 1.

    return X, proto_max_lmt
