import numpy as np
import math
import pickle as pkl
from tkinter import _flatten


def Euclidean_Distance(v1, v2):
    dis = np.linalg.norm(v1 - v2)
    return dis


def norm(X,delta=1e-10):  # X is a numpy array
    X_min = np.min(X)
    X_max = np.max(X)
    X = (X - X_min) / (X_max - X_min + delta)
    return (X, X_min, X_max)


def denorm(X, X_min, X_max,delta=1e-10):  # X is a numpy array
    X = X * (X_max - X_min + delta) + X_min
    return X


def logarithmic_compress(X,e = 16.):
    for i in range(X.shape[0]):
        for j in range(X.shape[1]):
            if X[i][j] <= 1. - e:
                X[i][j] = -math.log(-X[i][j] - 1., e)
            elif 1. - e < X[i][j] <= e - 1.:
                X[i][j] = 1. / (e - 1.) * X[i][j]
            else:
                X[i][j] = math.log(X[i][j] + 1., e)
    return X


def logarithmic_decompress(Y,e = 16.):
    for i in range(Y.shape[0]):
        for j in range(Y.shape[1]):
            if Y[i][j] <= -1.:
                try:
                    Y[i][j] = - e ** (-Y[i][j]) - 1.
                except OverflowError:
                    Y[i][j] = -float('inf')
            elif -1. < Y[i][j] <= 1.:
                Y[i][j] = (e - 1.) * Y[i][j]
            else:
                try:
                    Y[i][j] = e ** (Y[i][j]) - 1.
                except OverflowError:
                    Y[i][j] = float('inf')
    return Y


class Unit:
    def __init__(self,
                 grp_size,
                 max_cft_pkt
                 ):
        self.mal = np.zeros((grp_size, 2))
        # print(grp_size,max_cft_pkt)
        self.craft = np.zeros((grp_size, max_cft_pkt, 3))


class KNnormalizer:
    def __init__(self, model_save_path, dim=100):
        """
        :param dim: 特征的维数，int 
        model_save_path: KN模型参数，读取FM的相关信息
        """

        with open(model_save_path, 'rb') as f:
            self.FM = pkl.load(f)

        self.dim = dim
        self.norm_max = []
        self.norm_min = []
        for i in range(len(self.FM)):
            self.norm_max.append(np.ones(len(self.FM[i])) * -np.Inf)
            self.norm_min.append(np.ones(len(self.FM[i])) * np.Inf)

    def fit_transform(self, X):
        """
        fit归一化器，并转换训练集        
        :param X: 训练集原始特征 
        :return: 训练集归一化后特征
        """
        train_Feature = []
        X = np.array(X)
        for i in range(len(X)):
            train_feature = []
            for j in range(len(self.FM)):
                x = X[i][self.FM[j]]
                # update norms
                self.norm_max[j][x > self.norm_max[j]] = x[x > self.norm_max[j]]
                self.norm_min[j][x < self.norm_min[j]] = x[x < self.norm_min[j]]
                # 0-1 normalize
                x = (x - self.norm_min[j]) / (self.norm_max[j] - self.norm_min[j] + 0.0000000000000001)
                train_feature = np.concatenate((train_feature, x))
            train_Feature.append(train_feature)

        """此处将self.norm_max和self.norm_min展成一维，便于后续调用transform 测试集"""

        for i in range(len(self.FM)):
            self.norm_max[i] = self.norm_max[i].tolist()
            self.norm_min[i] = self.norm_min[i].tolist()

        self.norm_max = np.array(_flatten(self.norm_max))
        self.norm_min = np.array(_flatten(self.norm_min))
        self.FM = np.array(_flatten(self.FM))

        return np.array(train_Feature)

    def transform(self, X):
        """
        转换测试特征集（或其他），注意一定要先使用fit_transform函数后再使用本函数
        :param X: 待转换（归一化）的特征集
        :return: 转换（归一化）后的特征集
        """

        X = np.array(X)
        X[:, self.FM] = (X[:, self.FM] - self.norm_min) / (self.norm_max - self.norm_min + 0.0000000000000001)
        return X
