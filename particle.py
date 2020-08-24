from initializer import initialize
from rebuilder import rebuild
from AfterImageExtractor.FEKitsune import Kitsune
from AfterImageExtractor.KitsuneTools import *
import numpy as np
import copy
import random
from utils import *
from updater import generate_V, update_X
import time


class Particle:
    def __init__(
            self,
            last_end_time,  # initializer
            groupList,  # initializer
            max_time_extend,  # initializer
            max_cft_pkt,  # initializer
            min_time_extend,
            max_crafted_pkt_prob,
            show_info=False):

        self.show_info = show_info

        self.grp_size = len(groupList)
        self.groupList = groupList
        self.max_cft_pkt = max_cft_pkt
        self.max_time_extend = max_time_extend
        self.last_end_time = last_end_time
        self.proto_max_lmt = []

        self.pktList = None
        self.feature = None
        self.all_feature = None
        self.local_FE = None

        if self.show_info:
            print("----@Particle: Initializing...")

        # initialize X and V
        self.X, self.proto_max_lmt = initialize(self.grp_size, last_end_time,
                                                groupList, max_time_extend,
                                                max_cft_pkt, min_time_extend,
                                                max_crafted_pkt_prob)
        self.V = Unit(self.grp_size, self.max_cft_pkt)

        self.indi_best_X = None
        self.indi_best_dis = -1.
        self.dis = -1.

    def evaluate(self, mimic_set, nstat, knormer):

        # if self.show_info:
        # print("----@Particle: Evaluate distance...")

        self.pktList = rebuild(self.grp_size, self.X, self.groupList)

        mal_pos = []
        cft_num = 0
        for i in range(self.grp_size):
            cft_num += int(round(self.X.mal[i][1]))
            # print("##Debug##", "X.mal[i][1]", self.X.mal[i][1])
            mal_pos.append(i + cft_num)

        t1 = time.clock()

        self.local_FE = Kitsune(self.pktList, np.Inf, True)
        self.local_FE.FE.nstat = safelyCopyNstat(nstat, True)
        self.feature, self.all_feature = RunFE(self.local_FE,
                                               origin_pos=mal_pos)

        self.feature = np.asarray(self.feature)
        self.feature[:, 33:50:4] = 0.
        self.feature[:, 83:100:4] = 0.

        norm_feature = knormer.transform(self.feature)

        t2 = time.clock()

        FE_time = t2 - t1

        self.dis = 0

        for i in range(self.grp_size):
            self.dis += min(np.linalg.norm(norm_feature[i] - mimic_set,
                                           axis=1))

        if self.show_info:
            print("----@Particle: distance is", self.dis)

        # Update individual best (check to see if the current position is an individual best)
        if self.dis < self.indi_best_dis or self.indi_best_dis == -1:
            self.indi_best_X = self.X
            self.indi_best_dis = self.dis

        return FE_time

    # update new particle velocity
    def update_v(self, glob_best_X, w, c1, c2):

        if self.show_info:
            print("----@Particle: Update social velocity...")
        soc_V = generate_V(self.X, glob_best_X, self.grp_size,
                           self.max_cft_pkt)

        if self.show_info:
            print("----@Particle: Update cognitive velocity...")
        # print("self.indi_best_X",self.indi_best_X)
        cog_V = generate_V(self.X, self.indi_best_X, self.grp_size,
                           self.max_cft_pkt)

        r1 = random.random()
        r2 = random.random()

        # compute V
        self.V.mal = w * self.V.mal + c1 * r1 * cog_V.mal + c2 * r2 * soc_V.mal
        self.V.craft = w * self.V.craft + c1 * r1 * cog_V.craft + c2 * r2 * soc_V.craft

    # update the particle position based off new velocity updates
    def update_x(self):
        if self.show_info:
            print("----@Particle: Update position...")

        update_X(self.X, self.V, self.grp_size, self.max_cft_pkt,
                 self.last_end_time, self.groupList, self.max_time_extend,
                 self.proto_max_lmt)
