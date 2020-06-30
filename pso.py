"""
定义粒子群的行为
"""
"""
                                 ics_time                       
      |-----------------|+++++++++++++++++++++++|
last_end_time     groupList[-1].time      last_end_time(*) 
                                          cur_end_time
"""
from particle import Particle
import numpy as np
from scapy.all import *
# import KNKitsune as Ks
# from KitsuneTools import RunKN

# maxAE = 10          # maximum size for any autoencoder in the ensemble layer
# feature_size = 100

# KN = Ks.Kitsune(feature_size,maxAE)


class PSO:

    def __init__(self,max_iter,particle_num,grp_size=0,alg='L'):

        self.max_iter = max_iter  # 迭代次数
        self.particle_num = particle_num  # 粒子总数
        self.grp_size = grp_size  # 每个领域含有的粒子数

        self.grp_best_dis = [-1.] * (self.particle_num//self.grp_size)  # 记录每个淋邻域的最好dis
        self.grp_best_index = [-1] * (self.particle_num//self.grp_size)  # 记录每个淋邻域的最好粒子在swarm中的index

        self.global_best_dis = -1.  # 整个集群中最好的粒子的distance
        self.global_best_index = -1  # 整个集群中最好的粒子对应swarm中的下标

        self.global_best_pktlist = None  # 整个集群中最好的粒子的pktlist

        self.swarm = []  # 粒子群

        self.STA_glb_dis_list = []  # 记录该粒子群每个step最好的dis
        self.STA_avg_dis_list = []  # 记录该粒子群每个step平均的dis


    def execute(self,
                last_end_time,  # initializer
                groupList,  # initializer
                max_time_extend,  # initializer
                max_cft_pkt,  # initializer
                min_time_extend,
                max_crafted_pkt_prob,
                mimic_set,  # evaluate
                nstat, # evaluate
                # tmp_pcap_file,
                knormer,
                w,c1,c2,
                show_info = True,
                heuristic = False, 
                ):

        # print("*" * 64)
        # establish the swarm
        # print("--@PSO: Creating particle swarm...")
        for i in range(self.particle_num):
            # print("PSO:",max_cft_pkt)
            self.swarm.append(Particle(last_end_time,groupList,max_time_extend,max_cft_pkt,min_time_extend, max_crafted_pkt_prob))

        # begin optimization loop
        # print("--@PSO: Executing PSO algorithm...")
        FE_time = 0

        last_glb_best = np.Inf

        # for iter in range(max_iter):
        iter = 0
        while True:
            # 开始每一次迭代
            avg_dis = 0 # 用来计算STA_avg_dis_list
            for i in range(0,self.particle_num,self.grp_size):
                # 处理每一个小组
                # print("--@PSO: process grp %d, no.%d~%d"%(i/self.grp_size,i,i+self.grp_size-1), "...")
                for j in range(i,i+self.grp_size):
                    grp_i = int(i/self.grp_size)
                    FE_time += self.swarm[j].evaluate(mimic_set,nstat,knormer) # tmp_pcap_file
                    avg_dis += self.swarm[j].dis
                    # 更新当前小组的最小距离和最小距离对应的index
                    if self.swarm[j].dis < self.grp_best_dis[grp_i] or self.grp_best_dis[grp_i] == -1.:
                        self.grp_best_index[grp_i] = j
                        self.grp_best_dis[grp_i] = self.swarm[j].dis
                """
                # 处理完当前group的全部粒子，输出当前group的最好信息
                print("-"*64)
                print("(Step %d)"%iter, "Group", grp_i,
                      "Local best value:", self.grp_best_dis[grp_i],"Local best index:",self.grp_best_index[grp_i])
                print("--RMSE:",RunKitNet(KN,self.swarm[self.grp_best_index[grp_i]].feature))
                print("-"*64)
                """

                # 判断当前的group的值是不是全局最优的值，并更新全局最优(最好的小组对应的)的值和index
                if self.grp_best_dis[grp_i] < self.global_best_dis or self.global_best_dis == -1.:
                    self.global_best_index = self.grp_best_index[grp_i]
                    self.global_best_dis = self.grp_best_dis[grp_i]
                
                
                # 更新当前小组的V和X
                grp_best_X = self.swarm[self.grp_best_index[grp_i]].X  # 计算局部最优值，用于更新当前group

                for j in range(i, i + self.grp_size):
                    # print("--@PSO: update_V swarm", j, "...")
                    self.swarm[j].update_v(grp_best_X,w,c1,c2)
                    # print("--@PSO: update_X swarm", j, "...")
                    self.swarm[j].update_x()
                    # if j==0:
                        # print("after X is:")
                        # print( self.swarm[j].X.mal)
                        # print( self.swarm[j].X.craft)

            self.STA_glb_dis_list.append(self.global_best_dis)
            self.STA_avg_dis_list.append(avg_dis/self.particle_num)

            # 处理完全部小组（全部粒子），输出全局的最优信息
            # print("*"*64)
            if show_info:
                print("--@PSO:Step",iter,"Finished...Global best value:",self.global_best_dis)
            # print("  RMSE is:", RunKN(KN, self.swarm[self.global_best_index].feature))
            # print("*"*64)

            # 改进做法，下降iter次才停止
            if heuristic:
                if last_glb_best > self.global_best_dis*(1. + 0.1):  # delta must > 10%
                    last_glb_best = self.global_best_dis
                    iter -= 1
            iter += 1
            if iter >= self.max_iter:
                break

        self.global_best_pktlist = self.swarm[self.global_best_index].pktList
        # wrpcap(tmp_pcap_file,self.global_best_pktlist)  # 写入全局最好的pcap文件，等待global_FE读取后运行

        # 统计量计算和返回
        # STA_rmse = RunKN(KN, self.swarm[self.global_best_index].feature) # 最好的粒子对应的mal包的rmse
        # STA_all_rmse = RunKN(KN, self.swarm[self.global_best_index].all_feature) # 最好的粒子对应的全部包的rmse
        STA_best_X = self.swarm[self.global_best_index].X  # 最好的粒子对应的X
        STA_best_feature = self.swarm[self.global_best_index].feature  # 最好的粒子对应的仅含有mal的feature
        STA_best_pktList = self.global_best_pktlist  # 最好的粒子对应的全部包的的pktList

        STA_best_all_feature = self.swarm[self.global_best_index].all_feature

        # 计算最优解的cur_end_time 和 ics_time（详细见onenote图示）
        cur_end_time = self.swarm[self.global_best_index].X.mal[-1][0]
        ics_time = cur_end_time - float(groupList[-1].time)

        # print("*" * 64)
        return ics_time,cur_end_time,STA_best_X,STA_best_feature,STA_best_pktList,self.STA_glb_dis_list,self.STA_avg_dis_list,STA_best_all_feature,FE_time