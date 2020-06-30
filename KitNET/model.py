import numpy as np
import matplotlib.pyplot as plt
import pickle as pkl
import executeKitNET.KitNET as eKN
import trainKitNET.KitNET as tKN
import argparse

def RunKN(K,Feature):
    RMSEs = []
    for i,x in enumerate(Feature):
        rmse = K.proc_next_packet(x)
        if i%1000==0:
            print("--- RunKitNET: Pkts",i,"---")
        if rmse == -1:
            break
        RMSEs.append(rmse)
    return RMSEs


def test_mut(mut_feat,model_save_path):

    Feature_Size = mut_feat.shape[1]
    ekn = eKitsune(model_save_path, Feature_Size, 10)
    rmse = RunKN(ekn, mut_feat)

    return rmse

class eKitsune:
    
    def __init__(self,model_save_path,feature_size,max_autoencoder_size=10,learning_rate=0.1,hidden_ratio=0.75,):
        
        self.AnomDetector = eKN.KitNET(model_save_path,feature_size,max_autoencoder_size,learning_rate,hidden_ratio)

    def proc_next_packet(self,x):
        
        return self.AnomDetector.process(x)  # will train during the grace periods, then execute on all the rest.


class tKitsune:
    def __init__(self,model_save_path,n,max_autoencoder_size=10,FM_grace_period=None,AD_grace_period=10000,learning_rate=0.1,hidden_ratio=0.75,):

        self.AnomDetector = tKN.KitNET(model_save_path,n,max_autoencoder_size,FM_grace_period,AD_grace_period,learning_rate,hidden_ratio)

    def proc_next_packet(self,x):

        return self.AnomDetector.process(x)  # will train during the grace periods, then execute on all the rest.


if __name__ == "__main__":
    parse = argparse.ArgumentParser()

    parse.add_argument('-M', '--mode', type=str, default='exec', help="{train,exec}")

    parse.add_argument('-tf', '--feat_file_path', type=str, required=True, help="train or execute feature file path (.npy)")
    parse.add_argument('-rf', '--RMSE_file_path', type=str,
                       help="resulting rmse file (.pkl) path, only for execute mode!")

    parse.add_argument('-mf', '--model_file_path', type=str, default='./example/model.pkl',
                       help="for train mode, model is saved into 'mf'; for execute mode, model is loaded from 'mf'")

    parse.add_argument('-m', '--maxAE', type=int, default=10,
                       help="maximum size for any autoencoder in the ensemble layer")
    parse.add_argument('-fm', '--FMgrace', type=int, default=5000,
                       help="the number of instances taken to learn the feature mapping (the ensemble's architecture)")
    parse.add_argument('-ad', '--ADgrace', type=int, default=50000,
                       help="the number of instances used to train the anomaly detector (ensemble itself)")

    arg = parse.parse_args()

    if arg.mode == 'train':
        print("Warning: under TRAIN mode!")
        feature = np.load(arg.feat_file_path)
        feature = feature[:arg.FMgrace + arg.ADgrace]
        feature_size = feature.shape[1]

        tkn = tKitsune(arg.model_file_path, feature_size, arg.maxAE, arg.FMgrace, arg.ADgrace)
        rmse = RunKN(tkn, feature)
        AD_threshold = max(rmse[arg.FMgrace:])

        # x = np.arange(0,len(rmse),1)
        # plt.scatter(x,rmse)
        # plt.show()

        print("AD_threshold:", AD_threshold)

        with open(arg.model_file_path, "ab") as f:
            pkl.dump(AD_threshold, f)

    elif arg.mode == 'exec':
        print("Warning: under EXECUTE mode!")

        feature = np.load(arg.feat_file_path)
        # feature = feature[arg.FMgrace:]
        feature_size = feature.shape[1]

        # delete pcc-related features
        feature[:, 33:50:4] = 0.
        feature[:, 83:100:4] = 0.

        ekn = eKitsune(arg.model_file_path, feature_size, arg.maxAE)

        rmse = RunKN(ekn, feature)
        rmse = np.array(rmse)
        with open(arg.RMSE_file_path, 'wb') as f:
            pkl.dump(rmse, f)

        with open(arg.model_file_path, "rb") as f:
            _ = pkl.load(f)
            _ = pkl.load(f)
            _ = pkl.load(f)
            AD_threshold = pkl.load(f)

        print('AD_threshold:', AD_threshold)
        print('# rmse over AD_t:', rmse[rmse > AD_threshold].shape)
        print('Total number:', len(rmse))
        print("rmse mean:", np.mean(rmse))

        x = np.arange(0,len(rmse),1)
        plt.figure()
        plt.scatter(x,rmse,s=12, c='r')
        plt.plot(x,[AD_threshold]*len(rmse),c='black',linewidth=2,label="AD_threshold")
        plt.title("RMSE of Test set")
        plt.xlabel('pkt no.')
        plt.ylabel('RMSE in Kitsune')
        plt.legend()
        plt.show()


    else:
        raise RuntimeError("argument -M is wrong! choose 'train' or 'execute'")
    

