import numpy as np
import math


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
                 grp_size,  # 数据包组的包个数
                 max_cft_pkt  # 最多允许一个mal包携带多少个cft包
                 ):
        self.mal = np.zeros((grp_size, 2))
        # print(grp_size,max_cft_pkt)
        self.craft = np.zeros((grp_size, max_cft_pkt, 3))