"""
定义了每一个粒子（候选解）的行为
"""
"""
                                 ics_time                       
      |-----------------|+++++++++++++++++++++++|
last_end_time     groupList[-1].time      last_end_time(*) 
                                          cur_end_time
"""

from initializer import initialize
from rebuilder import rebuild
from AfExtractor.FEKitsune import Kitsune
from AfExtractor.KitsuneTools import RunFE
import numpy as np
import copy
import random
from utils import *
from updater import generate_V,update_X

# --- Empirical Parameters -----------------------------------------------------------+
# w = 0.5  # constant inertia weight (how much to weigh the previous velocity)
# c1 = 0.5  # cognitive constant
# c2 = 1  # social constant


class Particle:

    def __init__(self,
                 last_end_time,  # initializer
                 groupList,  # initializer
                 max_time_extend,  # initializer
                 max_cft_pkt,  # initializer
                 min_time_extend,
                 max_crafted_pkt_prob,
                 show_info=False
                 ):
        # 当前粒子是否输出提示信息
        self.show_info = show_info
        # 求解当前数据包组时所有粒子公用的相同变量
        self.grp_size = len(groupList)  # 当前粒子对应的数据包组中包个数
        self.groupList = groupList  # 当前粒子对应的数据包组的原始pcap
        self.max_cft_pkt = max_cft_pkt  # 最多允许一个mal包携带多少个cft包
        self.max_time_extend = max_time_extend  # 最大允许拉伸的时间间隔倍数
        self.last_end_time = last_end_time  # 上一个数据包组最后一个包的时间
        self.proto_max_lmt = []  # 协议层数`的最大值（每个mal包不同）

        # 每一粒子(在每一轮次)不同的变量
        self.pktList = None   # 粒子当前代表的pcap
        self.feature = None     # 粒子代表的pcap中mal经过FE的feature
        self.all_feature = None  # 粒子代表的pcap中全部的包经过FE的feature
        self.local_FE = None

        if self.show_info:
            print("----@Particle: Initializing...")

        # initialize X and V
        self.X,self.proto_max_lmt = initialize(self.grp_size, last_end_time, groupList, max_time_extend, max_cft_pkt, min_time_extend, max_crafted_pkt_prob) # 粒子位置
        self.V = Unit(self.grp_size,self.max_cft_pkt) # 粒子速度

        self.indi_best_X = None  # 记录粒子自身经历的最好位置
        self.indi_best_dis = -1.  # 记录粒子自身经历的最好位置对应的距离
        self.dis = -1.  # 当前轮次的距离信息


    # 计算粒子当前位置对应的距离信息
    def evaluate(self, mimic_set, nstat, tmp_pcap_file):

        if self.show_info:
            print("----@Particle: Evaluate distance...")

        self.pktList = rebuild(self.grp_size, self.X, self.groupList, tmp_pcap_file)

        # 计算mal_pos(当前序列中mal包的位置信息)
        mal_pos = []
        cft_num = 0
        for i in range(self.grp_size):
            cft_num += int(round(self.X.mal[i][1]))
            # print("##Debug##", "X.mal[i][1]", self.X.mal[i][1])
            mal_pos.append(i+cft_num)

        # local FE 运行生成新的feature
        self.local_FE = Kitsune(tmp_pcap_file, np.Inf)  # local FE读取运行rebuilder存在指定路径中的pcap文件
        self.local_FE.FE.nstat = copy.deepcopy(nstat)  # 因为会改变global FE 的nstat，所以要深拷贝
        self.feature,self.all_feature = RunFE(self.local_FE, origin_pos=mal_pos)

        # 压缩和归一化
        # Feature = np.array(copy.deepcopy(self.feature))  # 保留原始的feature，后续继续KN
        # Feature = logarithmic_compress(Feature)
        # Feature, _, _ = norm(Feature)

        # 使用mimic_set衡量和良性特征之间的距离
        self.dis = 0
        for i in range(self.grp_size):
            dis_list = []
            for j in range(mimic_set.shape[0]):
                dis_list.append(Euclidean_Distance(self.feature[i], mimic_set[j]))
            self.dis += min(dis_list)

        if self.show_info:
            print("----@Particle: distance is", self.dis)

        # 更新 individual best (check to see if the current position is an individual best)
        if self.dis < self.indi_best_dis or self.indi_best_dis == -1:
            self.indi_best_X = self.X
            self.indi_best_dis = self.dis

    # update new particle velocity
    def update_v(self, glob_best_X,w,c1,c2):

        if self.show_info:
            print("----@Particle: Update social velocity...")
        soc_V = generate_V(self.X, glob_best_X, self.grp_size, self.max_cft_pkt)

        if self.show_info:
            print("----@Particle: Update cognitive velocity...")
        cog_V = generate_V(self.X, self.indi_best_X, self.grp_size, self.max_cft_pkt)

        r1 = random.random()
        r2 = random.random()

        # 计算新的速度
        self.V.mal = w * self.V.mal + c1 * r1 * cog_V.mal + c2 * r2 * soc_V.mal
        self.V.craft = w * self.V.craft + c1 * r1 * cog_V.craft + c2 * r2 * soc_V.craft

    # update the particle position based off new velocity updates
    def update_x(self):
        if self.show_info:
            print("----@Particle: Update position...")

        update_X(self.X, self.V, self.grp_size, self.max_cft_pkt,self.last_end_time,self.groupList,self.max_time_extend,self.proto_max_lmt)



