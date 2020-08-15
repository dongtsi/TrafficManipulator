from scapy.all import *
import numpy as np
import matplotlib.pyplot as plt
import pickle as pkl
import sys
import argparse

from utils import *
sys.path.append('./KitNET')
from KitNET.model import test_mut


def Euclidean_Distance(v1, v2):
    dis = np.linalg.norm(v1 - v2)
    return dis


class Analyzer:
    def __init__(self,
                 org_rmse_file,
                 org_pcap_file,
                 sta_data_file,
                 model_save_path,
                 limit=None):

        self.del_num = 0

        self.org_pcap = rdpcap(org_pcap_file)

        with open(org_rmse_file, "rb") as f:
            self.org_rmse_list = pkl.load(f)
        self.org_rmse_list = np.array(self.org_rmse_list)

        with open(sta_data_file, "rb") as f:
            self.X_list = pkl.load(f)
            self.feature_list = pkl.load(f)
            self.pktList_list = pkl.load(f)

        self.len = len(self.org_pcap)
        self.grp_size = self.X_list[0].mal.shape[0]

        feature_list = []
        for i in self.feature_list:
            for j in i:
                feature_list.append(j)
        self.feature_list = np.asarray(feature_list)[:, :100]

        # pcc-related features
        self.feature_list[:, 33:50:4] = 0.
        self.feature_list[:, 83:100:4] = 0.
        self.feature_list[:, 32:49:4] = 0.
        self.feature_list[:, 82:99:4] = 0.

        # compiling mutated features
        self.rmse_list = test_mut(self.feature_list, model_save_path)
        self.rmse_list = np.array(self.rmse_list)

        # Analyzing partial data
        self.len = len(self.rmse_list)
        if limit is not None:
            print("Warning: Analyzing partial data", limit)
            self.len = limit
            self.rmse_list = self.rmse_list[:self.len]
            self.feature_list = self.feature_list[:self.len]
            self.glb_dis_list = self.glb_dis_list[:self.len]

        if len(self.rmse_list) < len(self.org_rmse_list) or limit is not None:
            print("Warning: Statistics are incomplete !", len(self.rmse_list),
                  "<", len(self.org_rmse_list))
            self.org_pcap = self.org_pcap[:self.len]
            self.org_rmse_list = self.org_rmse_list[:self.len]

    def del_outlier(self, extend=2):
        del_list = []
        # print(self.feature_list.shape)
        org_rmse_mean = np.mean(self.org_rmse_list)
        for i in range(self.len):
            if self.rmse_list[i] > self.org_rmse_list[
                    i] * extend or self.rmse_list[i] > org_rmse_mean * extend:
                self.rmse_list[i] = 0.
                del_list.append(i)
                for j in range(self.feature_list.shape[1]):
                    self.feature_list[i][j] = 0.
                self.del_num += 1

    def save_mutated_traffic(self, mut_pcap_path):
        true_time = []
        for x in self.X_list:
            for i in range(x.mal.shape[0]):
                for j in range(int(round(x.mal[i][1]))):
                    true_time.append(x.mal[i][0] - x.craft[i][j][0])
                true_time.append(x.mal[i][0])
        cnt = 0
        pkt_List = []
        for p in self.pktList_list:
            for pp in p:
                pp.time = true_time[cnt]
                cnt = cnt + 1
                pkt_List.append(pp)

        print("Total #pkts in mutated traffic:", len(pkt_List))
        wrpcap(mut_pcap_path, pkt_List)

    def eval(self,
             AD_threshold,
             mimic_set_file,
             test_feat_file,
             knormer_file,
             need_mmr=False):

        print("1.Time elapse:")
        b = self.org_pcap[-1].time - self.org_pcap[0].time
        a = self.X_list[-1].mal[-1][0] - self.X_list[0].mal[0][0]
        a = float(a)
        b = float(b)
        print("--Before:", b)
        print("--After :", a)
        print("--Rate:", (a - b) / b)
        print("====================================================")

        print("2.Pkt num:")
        b = self.len
        a = 0
        for x in self.X_list:
            for i in range(x.mal.shape[0]):
                a += int(round(x.mal[i][1]))
        print("--Before:", b)
        print("--After :", a + b)
        print("--cft :", a)
        print("--Rate:", a / b)
        print("====================================================")

        print("RMSE:")
        b = np.mean(self.org_rmse_list)
        a = np.mean(self.rmse_list)
        print("  original:", b, "mutated:", a)
        print("  PDR:", (b - a) / b)
        print("-" * 64)

        print("# Detected:")
        b = self.org_rmse_list[self.org_rmse_list > AD_threshold].shape[0]
        a = self.rmse_list[self.rmse_list > AD_threshold].shape[0]
        print("  original:", b, "mutated:", a)
        print("  PDR:", (b - a) / b)
        print("-" * 64)

        if need_mmr:
            mimic_feat = np.load(mimic_set_file)

            mal_feat = np.load(test_feat_file)[:self.len]
            mut_feat = self.feature_list

            with open(knormer_file, 'rb') as f:
                knormer = pkl.load(f)

            mal_feat = knormer.transform(mal_feat)
            mut_feat = knormer.transform(mut_feat)
            org_dis = 0.
            mut_dis = 0.

            for i in range(mal_feat.shape[0]):
                org_dis += max(np.linalg.norm(mal_feat[i] - mimic_feat,
                                              axis=1))
                mut_dis += min(np.linalg.norm(mut_feat[i] - mimic_feat,
                                              axis=1))
            MMR = 1. - mut_dis / org_dis
            print("Feature Changed:")
            print("  Before:", org_dis, "After:", mut_dis)
            print("  MMR:", MMR)

    def plt_rmse(self, AD_threshold):

        x = np.arange(0, self.len, 1)
        plt.figure()
        # plt.scatter(x, np.log(self.org_rmse_list), s=16,  c='#8A977B',alpha=0.5,label="Before")
        # plt.scatter(x, np.log(self.rmse_list), s=16, c='#FE4365',alpha=0.5,label="After")
        # plt.plot(x,[np.mean(np.log(self.org_rmse_list))]*self.len,c='#8A977B',alpha=0.5)
        # plt.plot(x,[np.mean(np.log(self.rmse_list))]*self.len, c='#FE4365',alpha=0.5)

        plt.scatter(x,
                    self.org_rmse_list,
                    s=12,
                    c='#8A977B',
                    alpha=0.5,
                    label="Before")
        plt.scatter(x,
                    self.rmse_list,
                    s=12,
                    c='#FE4365',
                    alpha=0.5,
                    label="After")
        plt.plot(x, [np.mean(self.org_rmse_list)] * self.len,
                 c='#8A977B',
                 alpha=0.3,
                 linewidth=4)
        plt.plot(x, [np.mean(self.rmse_list)] * self.len,
                 c='#FE4365',
                 alpha=0.3,
                 linewidth=4)
        plt.plot(x, [AD_threshold] * self.len,
                 c='black',
                 linewidth=2,
                 label="AD_threshold")
        plt.title("RMSE change and mean")
        plt.xlabel('pkt no.')
        plt.ylabel('RMSE in Kitsune')
        plt.legend(loc='upper right')

        # plt.savefig('./tmp.pdf')
        plt.show()


if __name__ == "__main__":

    parse = argparse.ArgumentParser()
    parse.add_argument('-op',
                       '--org_pcap_file',
                       type=str,
                       required=True,
                       help="original malicious (test) traffic (.pcap)")

    parse.add_argument(
        '-or',
        '--org_rmse_file',
        type=str,
        required=True,
        help="original RMSE file of test malicious traffic (.pkl)")

    parse.add_argument('-of',
                       '--org_feat_file',
                       type=str,
                       help="original (test) feature (.npy)")

    parse.add_argument('-b',
                       '--mimic_set',
                       type=str,
                       required=True,
                       help="benign features to mimic (.npy)")

    parse.add_argument('-n',
                       '--normalizer',
                       type=str,
                       required=True,
                       help="compiled feature normalizer (.pkl)")

    parse.add_argument('-sf',
                       '--sta_file',
                       type=str,
                       default='./example/statistics.pkl',
                       help="statistics to read(.pkl)")

    parse.add_argument('-mf',
                       '--model_file_path',
                       type=str,
                       default='./example/model.pkl',
                       help="model_file after training")

    arg = parse.parse_args()

    a = Analyzer(
        org_rmse_file=arg.org_rmse_file,
        org_pcap_file=arg.org_pcap_file,
        sta_data_file=arg.sta_file,
        model_save_path=arg.model_file_path,
        # limit = 10000
    )

    with open(arg.model_file_path, 'rb') as f:
        _ = pkl.load(f)
        _ = pkl.load(f)
        _ = pkl.load(f)
        AD_threshold = pkl.load(f)
    print("AD_threshold:", AD_threshold)

    a.eval(AD_threshold,
           arg.mimic_set,
           arg.org_feat_file,
           arg.normalizer,
           need_mmr=True)
    a.plt_rmse(AD_threshold)
