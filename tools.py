import pickle as pkl
import numpy as np
import argparse
from utils import *

if __name__ == "__main__":

    parse = argparse.ArgumentParser()

    parse.add_argument('-M', '--mode', type=str, default='CK', help="{CK:compiling KNnormalizer,}")

    parse.add_argument('-tf', '--feat_file_path', type=str, default='./example/train_ben.npy', help="train feature file path(.npy)")

    parse.add_argument('-mf', '--model_file_path', type=str, default='./example/model.pkl',
                       help="model saved file path (.pkl)")

    parse.add_argument('-nf', '--normalizer_file_path', type=str, default='./example/normalizer.pkl',
                       help="normalizer file path to save (.pkl)")

    parse.add_argument('-fm', '--FMgrace', type=int, default=5000,
                       help="the number of instances taken to learn the feature mapping (the ensemble's architecture)")
    parse.add_argument('-ad', '--ADgrace', type=int, default=50000,
                       help="the number of instances used to train the anomaly detector (ensemble itself)")

    arg = parse.parse_args()

    train_feat = np.load(arg.feat_file_path)
    knormer = KNnormalizer(arg.model_file_path)
    knormer.fit_transform(train_feat[arg.FMgrace:arg.ADgrace])

    with open(arg.normalizer_file_path,'wb') as f:
        pkl.dump(knormer,f)
