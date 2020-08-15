import numpy as np
import math
import pickle as pkl
from tkinter import _flatten


def Euclidean_Distance(v1, v2):
    dis = np.linalg.norm(v1 - v2)
    return dis


class Unit:
    def __init__(self, grp_size, max_cft_pkt):
        self.mal = np.zeros((grp_size, 2))
        # print(grp_size,max_cft_pkt)
        self.craft = np.zeros((grp_size, max_cft_pkt, 3))


class KNnormalizer:
    def __init__(self, model_save_path, dim=100):
        with open(model_save_path, 'rb') as f:
            self.FM = pkl.load(f)

        self.dim = dim
        self.norm_max = []
        self.norm_min = []
        for i in range(len(self.FM)):
            self.norm_max.append(np.ones(len(self.FM[i])) * -np.Inf)
            self.norm_min.append(np.ones(len(self.FM[i])) * np.Inf)

    def fit_transform(self, X):
        train_Feature = []
        X = np.array(X)
        for i in range(len(X)):
            train_feature = []
            for j in range(len(self.FM)):
                x = X[i][self.FM[j]]
                # update norms
                self.norm_max[j][x > self.norm_max[j]] = x[
                    x > self.norm_max[j]]
                self.norm_min[j][x < self.norm_min[j]] = x[
                    x < self.norm_min[j]]
                # 0-1 normalize
                x = (x - self.norm_min[j]) / (
                    self.norm_max[j] - self.norm_min[j] + 0.0000000000000001)
                train_feature = np.concatenate((train_feature, x))
            train_Feature.append(train_feature)

        for i in range(len(self.FM)):
            self.norm_max[i] = self.norm_max[i].tolist()
            self.norm_min[i] = self.norm_min[i].tolist()

        self.norm_max = np.array(_flatten(self.norm_max))
        self.norm_min = np.array(_flatten(self.norm_min))
        self.FM = np.array(_flatten(self.FM))

        return np.array(train_Feature)

    def transform(self, X):
        X = np.array(X)
        X[:, self.FM] = (X[:, self.FM] - self.norm_min) / (
            self.norm_max - self.norm_min + 0.0000000000000001)
        return X
