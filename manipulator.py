from pso import PSO
from AfterImageExtractor.FEKitsune import Kitsune
from AfterImageExtractor.KitsuneTools import *
import numpy as np
import pickle as pkl
from scapy.all import *
from utils import *

import platform
import os
import sys

import datetime
from decimal import *
import argparse

# statistics for eval

STA_X_list = []
STA_feature_list = []
STA_pktList_list = []
STA_gbl_dis_list = []
STA_avg_dis_list = []
STA_all_feature_list = []


class Manipulator:

    # Manipulator Parameters
    grp_size = 5
    min_time_extend = 0.
    max_time_extend = 5.
    max_cft_pkt = 5
    max_crafted_pkt_prob = 1.

    # Particle Parameters
    w = 0.4
    c1 = 0.5
    c2 = 1.

    # PSO Parameters
    pso_iter = 10
    pso_num = 20
    pso_size = 5

    # Data Members
    pktList = []
    global_FE = None
    mimic_set = None

    def __init__(
            self,
            mal_pcap_file,
            mimic_set,
            knormer_file,
            init_pcap_file="./data/empty.pcap",  # preparatory traffic
    ):
        print("@Manipulator: Initializing ...")

        self.mimic_set = np.load(mimic_set)

        print("self.mimic_set.shape", self.mimic_set.shape)

        # Normalizer
        with open(knormer_file, 'rb') as f:
            self.knormer = pkl.load(f)

        self.pktList = rdpcap(mal_pcap_file)
        print("  read %d packets in malicious pcap" % (len(self.pktList)))

        # Create global feature extractor
        init_scapy_in = rdpcap(init_pcap_file)
        self.global_FE = Kitsune(init_scapy_in, np.Inf)

        # compile preparatory traffic if exists
        if init_pcap_file != "./data/empty.pcap":
            RunFE(self.global_FE)

    def change_manipulator_params(self,
                                  grp_size=5,
                                  max_time_extend=5.,
                                  max_cft_pkt=5,
                                  min_time_extend=0.,
                                  max_crafted_pkt_prob=1.):
        self.grp_size = grp_size
        self.max_time_extend = max_time_extend
        self.max_cft_pkt = max_cft_pkt
        self.min_time_extend = min_time_extend
        self.max_crafted_pkt_prob = max_crafted_pkt_prob

    def change_pso_params(self, max_iter=10, particle_num=20, grp_size=5):
        self.pso_iter = max_iter
        self.pso_num = particle_num
        self.pso_size = grp_size

    def change_particle_params(self, w=0.4, c1=0.5, c2=1.):
        self.w = w
        self.c1 = c1
        self.c2 = c2

    def save_configurations(self, config_file):

        print("@Mani: Save configurations...")
        with open(config_file, "w") as f:
            f.write("+----Highlight----+\r\n")
            f.write('(iter,swarm,delay,mimic) (' + str(self.pso_iter) + ',' +
                    str(self.pso_num) + ',' + str(self.max_time_extend) + ',' +
                    str(len(self.mimic_set)) + ")\r\n")
            f.write("-" * 96 + "\r\n")
            f.write("Feature extractor: AfterImage\r\n")
            f.write("-" * 96 + "\r\n")
            f.write("(Manipulator Params)\r\n")
            f.write("  grp_size:        " + str(self.grp_size) + "\r\n")
            f.write("  min_time_extend: " + str(self.min_time_extend) + "\r\n")
            f.write("  max_time_extend: " + str(self.max_time_extend) + "\r\n")
            f.write("  max_cft_pkt:     " + str(self.max_cft_pkt) + "\r\n")
            f.write("  min_cft_pkt_prob:" + str(0) + "\r\n")
            f.write("  max_cft_pkt_prob:" + str(self.max_crafted_pkt_prob) +
                    "\r\n\r\n")
            f.write("(PSO Params)\r\n")
            f.write("  pso_iter:        " + str(self.pso_iter) + "\r\n")
            f.write("  pso_num:         " + str(self.pso_num) + "\r\n")
            f.write("  pso_size:        " + str(self.pso_size) + "\r\n\r\n")
            f.write("(Particle Params)\r\n")
            f.write("  w:               " + str(self.w) + "\r\n")
            f.write("  c1:              " + str(self.c1) + "\r\n")
            f.write("  c2:              " + str(self.c2) + "\r\n")
            f.write("-" * 96 + "\r\n")

    def process(
        self,
        sta_file,
        start_no=0,
        limit=np.Inf,
        heuristic=False,
    ):

        # Timers
        FE_time = 0
        import time
        timer = time.time()

        acc_ics_time = 0
        last_end_time = float(self.pktList[0].time)
        begin_timestamp = float(self.pktList[0].time)

        st = start_no
        ed = st + self.grp_size

        print("@Mani: Begin processing...")
        while True:
            print("@Manipulator: Processing pkt ( %d to %d ) ..." % (st, ed))

            # print("@Manipulator: Create PSO")
            # ---- initialize PSO--------------------------------------------+
            pso = PSO(max_iter=self.pso_iter,
                      particle_num=self.pso_num,
                      grp_size=self.pso_size)

            # ---- load a new pkt group--------------------------------------+
            groupList = self.pktList[st:ed]

            # ---- increase initial time of the new pkt group----------------+
            for pkt in groupList:
                # pkt.time += Decimal(acc_ics_time)
                # pkt.time += acc_ics_time
                pkt.time = float(pkt.time) + acc_ics_time

            # ---- execute PSO-----------------------------------------------+
            pso_show_info = True
            if self.grp_size < 50:
                pso_show_info = False
            ics_time, cur_end_time, \
            STA_best_X, STA_best_feature, STA_best_pktList, STA_gbl_dis, STA_avg_dis,STA_best_all_feature,fe_time\
                        = pso.execute(  last_end_time, groupList,
                                        self.max_time_extend,self.max_cft_pkt, self.min_time_extend, self.max_crafted_pkt_prob,
                                        self.mimic_set,
                                        self.global_FE.FE.nstat,
                                        self.knormer,
                                        self.w,self.c1,self.c2,
                                        pso_show_info,heuristic)

            FE_time += fe_time
            # ---- prepare for next pkt group--------------------------------+
            acc_ics_time += ics_time
            last_end_time = cur_end_time

            ttime1 = time.clock()
            nstat = self.global_FE.FE.nstat
            self.global_FE = Kitsune(STA_best_pktList, np.Inf, False)
            self.global_FE.FE.nstat = safelyCopyNstat(nstat, False)
            RunFE(self.global_FE)
            ttime2 = time.clock()
            FE_time += (ttime2 - ttime1)

            # ---- Update statistics ----------------------------------------------+
            global STA_X_list
            global STA_feature_list
            global STA_pktList_list
            global STA_gbl_dis_list
            global STA_avg_dis_list

            STA_X_list.append(STA_best_X)
            STA_feature_list.append(STA_best_feature)
            STA_pktList_list.append(STA_best_pktList)
            STA_gbl_dis_list.append(STA_gbl_dis)
            STA_avg_dis_list.append(STA_avg_dis)
            STA_all_feature_list.append(STA_best_all_feature)

            # ---plt and dump info-------------------------------------------+
            if st != 0 and (st % 1000 == 0
                            or ed == len(self.pktList)) or ed == limit:
                print("@Manipulator:Time elapsed:", time.time() - timer)
                with open(sta_file, "wb") as f:
                    pkl.dump(STA_X_list, f)
                    pkl.dump(STA_feature_list, f)
                    pkl.dump(STA_pktList_list, f)
                    pkl.dump(STA_gbl_dis_list, f)
                    pkl.dump(STA_avg_dis_list, f)
                    pkl.dump(STA_all_feature_list, f)
                print("@Manipulator:statistics.pkl is updated...")

            # ---------------update `st` and `ed` for next loop--------------+
            if ed == len(self.pktList) or ed == limit:
                print("@Manipulator:All Finished!", ed,
                      "Pkts Processed,Time elapsed:",
                      time.time() - timer, "FE_time:", FE_time)
                break

            st = ed
            ed += self.grp_size
            if ed >= len(self.pktList):
                ed = len(self.pktList)
                self.grp_size = ed - st
            if ed >= limit:
                ed = limit
                self.grp_size = ed - st
