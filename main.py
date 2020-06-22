import numpy as np
import pickle as pkl
from scapy.all import *
import argparse
from manipulator import Manipulator

parse = argparse.ArgumentParser()
parse.add_argument('-m', '--mal_pcap', type=str, required=True, help="input malicious traffic (.pcap)")

parse.add_argument('-b', '--mimic_set', type=str, required=True, help="benign features to mimic (.csv)")

parse.add_argument('-i', '--init_pcap', type=str, default='_empty.pcap', help="preparatory traffic (ignore this if you don't need)")

parse.add_argument('-oF', '--mutated_feature', type=str, default='mutated_features.npy', help="features after mutation (.pkl)")
parse.add_argument('-oT', '--mutated_traffic', type=str, default='mutated_traffic.pcap', help="traffic after mutation (.pcap)")
                   
arg = parse.parse_args()

mimic_set = np.loadtxt(arg.mimic_set, delimiter=",")

m = Manipulator(arg.mal_pcap,mimic_set,arg.init_pcap)

# Choose Params
m.change_particle_params(w=0.6,c1=0.7,c2=1.4)
m.change_pso_params(max_iter=5,particle_num=10,grp_size=5)
m.change_manipulator_params(grp_size=5,
                            min_time_extend=0.,
                            max_time_extend=5.,
                            max_cft_pkt=4,
                            max_crafted_pkt_prob=0.3)

# 保存配置参数
# m.save_configurations('./configurations.txt')

tmp_pcap_file = "_crafted.pcap"
sta_file = "_statistics.pkl"
m.process(tmp_pcap_file,sta_file) # use limit=20 to test 

# 保存mutate之后的feature和traffic
with open(sta_file, "rb") as f:
    X_list = pkl.load(f)  # 每一组新的流量中最优粒子位置信息
    feature_list = pkl.load(f)  # 每一组新的流量中mal包经过FE的feature
    pktList_list = pkl.load(f)  # 每一组新的流量的原始信息（scapy的packet列表形式)
    glb_dis_list = pkl.load(f)
    avg_dis_list = pkl.load(f)

feature_list = np.asarray(feature_list)
feature_list = np.reshape(feature_list,(-1,feature_list.shape[-1]))
np.save(arg.mutated_feature,feature_list)

pktList = []
for i in range(len(pktList_list)):
    for p in pktList_list[i]:
        pktList.append(p)
wrpcap(arg.mutated_traffic,pktList)

print("@Main.py:Mutated features and traffic have been saved in file...")
print("All Finished Successfully!")




