
from pso import PSO
from AfExtractor.FEKitsune import Kitsune
from AfExtractor.KitsuneTools import RunFE
import AfExtractor.FeatureExtractor
import numpy as np
import pickle as pkl
from scapy.all import *
from utils import norm,logarithmic_compress

import platform
import os
import sys
import argparse


# 保存在pkl文件中的统计量

STA_X_list = []  # 每一组新的流量中最优粒子位置信息X
STA_feature_list = []  # 每一组新的流量中mal包经过FE的feature
STA_pktList_list = []  # 每一组新的流量的原始信息（scapy的packet列表形式）
STA_gbl_dis_list = []  
STA_avg_dis_list = []

class Manipulator:

    # Manipulator可选参数
    grp_size = 5  # number of mal packets in a pkt group
    max_time_extend = 5    # 最大允许拉伸的时间间隔倍数
    max_cft_pkt = 5  # 最多允许一个mal包携带多少个cft包
    min_time_extend = 0.  # 最小扩展时间的倍数 
    max_crafted_pkt_prob = 1. # 最大生成伪造包的概率
    
    # Particle可选参数
    w = 0.4
    c1 = 0.5
    c2 = 1.
    
    # PSO可选参数
    pso_iter = 10
    pso_num = 20
    pso_size = 5

    # 成员变量
    pktList = []  # original packets read by scapy
    global_FE = None  # global feature extractor
    mimic_set = None  # 良性特征模板集合

    def __init__(self,
                 mal_pcap_file,                         # 原始恶意数据包文件路径
                 mimic_set,                             # 良性特征集合文件路径
                 init_pcap_file="_empty.pcap",    # 需要提前输入的流量路径（默认是空的/空文件）
                 ):
        print("@Manipulator: Initializing ...")

        # 输入的参数
        self.mimic_set = mimic_set

        # 读取恶意数据包文件
        self.pktList = rdpcap(mal_pcap_file)
        print("@Manipulator: read %d packets in malicious pcap" % (len(self.pktList)))

        # 创建全局的特征提取器
        self.global_FE = Kitsune(init_pcap_file,np.Inf)

        # 如果需要输入准备的流量，则先运行特征提取器
        if init_pcap_file != "_empty.pcap":
            RunFE(self.global_FE)

    def change_manipulator_params(self,grp_size=5,max_time_extend=5,max_cft_pkt=5,min_time_extend=0.,max_crafted_pkt_prob=1.):
        self.grp_size = grp_size
        self.max_time_extend = max_time_extend
        self.max_cft_pkt = max_cft_pkt
        self.min_time_extend = min_time_extend  # 最小扩展时间的倍数 
        self.max_crafted_pkt_prob = max_crafted_pkt_prob # 最大生成伪造包的概率

    def change_pso_params(self,max_iter=10,particle_num=20,grp_size=5):
        self.pso_iter = max_iter
        self.pso_num = particle_num
        self.pso_size = grp_size
    
    def change_particle_params(self,w=0.4,c1=0.5,c2=1.):
        self.w = w
        self.c1 = c1
        self.c2 = c2

    def save_configurations(self,config_file):

        print("@Mani: Save configurations...")
        with open(config_file,"w") as f:
            f.write("-"*96+"\r\n")
            f.write("Feature extractor: AfterImage\r\n")
            f.write("-"*96+"\r\n")
            f.write("(Manipulator Params)\r\n")
            f.write("  grp_size:        " + str(self.grp_size)+"\r\n")
            f.write("  min_time_extend: " + str(self.min_time_extend)+"\r\n")
            f.write("  max_time_extend: " + str(self.max_time_extend)+"\r\n")
            f.write("  max_cft_pkt:     " + str(self.max_cft_pkt)+"\r\n")
            f.write("  min_cft_pkt_prob:" + str(0)+"\r\n")
            f.write("  max_cft_pkt_prob:" + str(self.max_crafted_pkt_prob)+"\r\n\r\n")
            f.write("(PSO Params)\r\n")
            f.write("  pso_iter:        " + str(self.pso_iter)+"\r\n")
            f.write("  pso_num:         " + str(self.pso_num)+"\r\n")
            f.write("  pso_size:        " + str(self.pso_size)+"\r\n\r\n")
            f.write("(Particle Params)\r\n")
            f.write("  w:               " + str(self.w)+"\r\n")
            f.write("  c1:              " + str(self.c1)+"\r\n")
            f.write("  c2:              " + str(self.c2)+"\r\n")
            f.write("-"*96+"\r\n")

    def process(self,
                # mimic_set,          # 良性特征集合文件路径  
                tmp_pcap_file,
                sta_file,
                start_no=0,
                limit=np.Inf):

        print("@Manipulator: Begin processing...")
        
        # 创建计时器
        import time
        timer = time.time()

        acc_ics_time = 0  # 累积的增长时间
        last_end_time = self.pktList[0].time
        begin_timestamp = self.pktList[0].time  # 第一个mal包的时间

        # 循环变量
        st = start_no
        ed = st + self.grp_size

        # 每次处理序号为[st.ed)的恶意数据包
        while True:
            print("@Manipulator: Processing pkt ( %d to %d ) ..."%(st,ed))

            print("@Manipulator: Create PSO")
            # ---- initialize PSO--------------------------------------------+
            pso = PSO(max_iter=self.pso_iter, particle_num=self.pso_num, grp_size=self.pso_size)

            # ---- load a new pkt group--------------------------------------+
            groupList = self.pktList[st:ed]

            # ---- increase initial time of the new pkt group----------------+
            for pkt in groupList:
                pkt.time += acc_ics_time
            # ---- execute PSO-----------------------------------------------+
            ics_time, cur_end_time, \
            STA_best_X, STA_best_feature, STA_best_pktList, STA_gbl_dis, STA_avg_dis\
                        = pso.execute(last_end_time, groupList, self.max_time_extend,self.max_cft_pkt, self.min_time_extend, self.max_crafted_pkt_prob,
                                       self.mimic_set, self.global_FE.FE.nstat,tmp_pcap_file,
                                       self.w,self.c1,self.c2)

            # ---- prepare for next pkt group--------------------------------+
            acc_ics_time += ics_time
            last_end_time = cur_end_time

            nstat = self.global_FE.FE.nstat
            self.global_FE = Kitsune(tmp_pcap_file, np.Inf)
            self.global_FE.FE.nstat = nstat
            RunFE(self.global_FE)

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


            # ---- print Info-----------------------------------------------+
            # print("+" * 72)
            # print("@Manipulator: Grp Finished...")
            # print("org RMSE is:", STA_org_rmse[st:ed])
            # print("cft RMSE is:", STA_rmse)
            # print("org_mal_num:", STA_org_mal_num, "| cft_mal_num:", STA_cft_mal_num)
            # if STA_org_mal_num > 0:
            #     print("evasion rate:",(STA_org_mal_num - STA_cft_mal_num) / STA_org_mal_num)
            # print("org mean is:", np.mean(STA_org_rmse[:ed]), "| c mean is:", np.mean(STA_cft_rmse[:ed]))
            # print("acc_ics_time:",acc_ics_time)
            print("-" * 72)

            # ---plt and dump info-------------------------------------------+
            if ed == len(self.pktList) or ed == limit: # st%50==0 or
                print("@Manipulator:Time elapsed:",time.time()-timer)
                with open(sta_file,"wb") as f:
                    pkl.dump(STA_X_list,f)
                    pkl.dump(STA_feature_list,f)
                    pkl.dump(STA_pktList_list,f)
                    pkl.dump(STA_gbl_dis_list,f)
                    pkl.dump(STA_avg_dis_list,f)
                print("@Manipulator:statistics.pkl is updated...")

            # ---------------update `st` and `ed` for next loop--------------+
            # 结束条件
            if ed == len(self.pktList) or ed == limit:
                print("@Manipulator:All Finished!", ed, "Pkts Processed,Time elapsed:", time.time() - timer)
                break

            st = ed
            ed += self.grp_size
            if ed >= len(self.pktList):
                ed = len(self.pktList)
                self.grp_size = ed - st
        

if __name__ == "__main__":


    parse = argparse.ArgumentParser()
    parse.add_argument('-m', '--mal_pcap', type=str, required=True, help="input malicious traffic (.pcap)")
    
    parse.add_argument('-b', '--mimic_set', type=str, required=True, help="benign features to mimic (.csv)")
    
    parse.add_argument('-i', '--init_pcap', type=str, default='_empty.pcap', help="preparatory traffic (ignore this if you don't need)")
    
    parse.add_argument('-o', '--sta_file', type=str, default='__statistics__.pkl', help="file saving the final statistics (.pkl)")
    
                       
    arg = parse.parse_args()
    
    mimic_set = np.loadtxt(arg.mimic_set, delimiter=",")
    
    m = Manipulator(arg.mal_pcap,mimic_set,arg.init_pcap)
    
    # 选择配置参数
    m.change_particle_params(w=0.6,c1=0.7,c2=1.4)
    m.change_pso_params(max_iter=3,particle_num=8,grp_size=4)
    m.change_manipulator_params(grp_size=5,
                                min_time_extend=0.,
                                max_time_extend=2.,
                                max_cft_pkt=3,
                                max_crafted_pkt_prob=0.3)

    # 保存配置参数
    # m.save_configurations('./configurations.txt')
    
    tmp_pcap_file = "_crafted.pcap"
    m.process(tmp_pcap_file,arg.sta_file,limit=20)


