"""
根据两个X生成V；根据V更新X
"""

"""
X_mal:
    [][0|1]  [mal包编号][时间点|伪造包个数]
X_craft:
    [][][0|1|2]  [mal包编号][伪造包序号][时间间隔|协议层数|数据长度]       
"""
import numpy as np
from utils import Unit

D = 10000  # mal_itv_lmt 的除数
DD = 1000  # cft_itv_lmt 的除数

"""对于craft部分X和b_X不同的情况，只处理X的部分，剩下的不产生"""
def generate_V(
                X,
                best_X,
                grp_size,
                max_cft_pkt
              ):
    # 初始化全0的V
    V = Unit(grp_size,max_cft_pkt)

    # 首先对mal部分产生V
    V.mal = best_X.mal - X.mal

    # 按mal包顺序遍历全部cft包产生V
    for i in range(grp_size):
        for j in range(int(round(X.mal[i][1]))):
            V.craft[i][j] = best_X.craft[i][j] - X.craft[i][j]

    return V


def update_X(
                X,
                V,
                grp_size,
                max_cft_pkt,
                last_end_time,
                groupList,
                max_time_extend,
                proto_max_lmt  # 协议层数`的最大值（每个mal包不同）
            ):

    # 计算最大允许的序列全部经过时间（用于计算mal_itv_lmt）
    max_mal_itv = (groupList[-1].time - last_end_time) * (max_time_extend+1)

    # 计算mal的最小间距限制（每个粒子在init后时固定的）
    mal_itv_lmt = max_mal_itv / D
    # mal_itv_lmt = 0

    # 更新mal中`时间点`并判断范围(注意需要异步按顺序更新，不能同步更新)
    for i in range(grp_size):
        targt_time = X.mal[i][0] + V.mal[i][0]
        if i == 0:
            if targt_time < last_end_time + mal_itv_lmt:
                X.mal[i][0] = last_end_time + mal_itv_lmt
            elif grp_size>1: # 当grp_size>1的时候
                if targt_time > X.mal[i + 1][0] - mal_itv_lmt:
                    X.mal[i][0] = X.mal[i + 1][0] - mal_itv_lmt
                else:
                    X.mal[i][0] = targt_time
            else:
                X.mal[i][0] = targt_time
        elif i == grp_size-1:
            if targt_time < X.mal[i-1][0] + mal_itv_lmt:
                X.mal[i][0] = X.mal[i-1][0] + mal_itv_lmt
            elif targt_time > (last_end_time + max_mal_itv) - mal_itv_lmt:
                X.mal[i][0] = (last_end_time + max_mal_itv) - mal_itv_lmt
            else:
                X.mal[i][0] = targt_time
        else:
            if targt_time < X.mal[i-1][0] + mal_itv_lmt:
                X.mal[i][0] = X.mal[i-1][0] + mal_itv_lmt
            elif targt_time > X.mal[i + 1][0] - mal_itv_lmt:
                X.mal[i][0] = X.mal[i + 1][0] - mal_itv_lmt
            else:
                X.mal[i][0] = targt_time

    # 更新mal的`伪造包个数` ，并去增加伪造包
    for i in range(grp_size):
        if V.mal[i][1] < 0:  # 当减少craft包时,不处理craft的部分
            X.mal[i][1] += V.mal[i][1]  # 直接变化
            if X.mal[i][1] < 0:
                X.mal[i][1] = 0.
        else:  # 当增加craft包时
            if X.mal[i][1] + V.mal[i][1] > max_cft_pkt:
                ics_cft_num = max_cft_pkt - round(X.mal[i][1])  # 记录一共需要增加多少cft包
                targt_cft_num = max_cft_pkt  # 记录最终的X.mal[i][1]变成了多少（先不更新，保留mal原来的cft个数）
            else:
                ics_cft_num = round(X.mal[i][1] + V.mal[i][1]) - round(X.mal[i][1])  # 注意不是V.mal[i][1]
                targt_cft_num = X.mal[i][1] + V.mal[i][1]
            # 开始增加craft部分
            for j in range(int(ics_cft_num)):
                if round(X.mal[i][1]) == 0: # 如果此mal原来没有cft包
                    if i==0:  # 如果此mal包是第一个mal包
                        itv = X.mal[i][0] - last_end_time  # itv 是留给新增的cft包的全部时间间隔，将会被平分
                    else:
                        itv = X.mal[i][0] - X.mal[i-1][0]
                else: # 如果此mal原来有cft包
                    itv = X.craft[i][int(round(X.mal[i][1]))-1][0]
                X.craft[i][int(round(X.mal[i][1]))+j][0] = (itv/ics_cft_num)*(j+1)
            # 最后更新X.mal[i][1]
            X.mal[i][1] = targt_cft_num


    # 更新craft中的`时间间隔`（先判断再更新）
    for i in range(grp_size):
        targt_itv = X.craft[i][0][0] + V.craft[i][0][0]  # 目标位置

        if i == 0:  # 当前的mal包是第一个时
            cft_itv_lmt = (X.mal[i][0]-last_end_time)/DD   # craft包的最小间隔限制，对于每个mal包是不同的

            if round(X.mal[i][1]) == 1:  # 当前的mal包只有1个cft包时
                if X.mal[i][0] - targt_itv < last_end_time + cft_itv_lmt:  # craft包太靠前了
                    X.craft[i][0][0] = X.mal[i][0] - (last_end_time + cft_itv_lmt)
                elif targt_itv < cft_itv_lmt:  # craft包太靠后了(下面都是按照这个太靠前-太靠后这个顺序判断)
                    X.craft[i][0][0] = cft_itv_lmt
            elif round(X.mal[i][1]) > 1:  # 当前的mal包有超过1个cft包时
                for j in range(int(round(X.mal[i][1]))):
                    if j==0:  # 对于（第一个mal包的）第一个craft包
                        if X.mal[i][0] - targt_itv < last_end_time + cft_itv_lmt:
                            X.craft[i][j][0] = X.mal[i][0] - (last_end_time + cft_itv_lmt)
                        elif targt_itv < X.craft[i][j+1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j+1][0] + cft_itv_lmt
                    elif j==round(X.mal[i][1])-1:  # 对于最后一个craft包
                        if targt_itv > X.craft[i][j-1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j-1][0] - cft_itv_lmt
                        elif targt_itv < cft_itv_lmt:
                            X.craft[i][j][0] = cft_itv_lmt
                    else:  # 对于中间的craft包
                        if targt_itv > X.craft[i][j-1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j-1][0] - cft_itv_lmt
                        elif targt_itv < X.craft[i][j+1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j+1][0] + cft_itv_lmt

        else:  # 当前的mal包不是第一个时
            cft_itv_lmt = (X.mal[i][0] - X.mal[i-1][0]) / DD  # craft包的最小间隔限制，对于每个mal包是不同的
            if round(X.mal[i][1]) == 1:  # 当前的mal包只有1个cft包时
                if X.mal[i][0] - targt_itv < X.mal[i-1][0] + cft_itv_lmt:
                    X.craft[i][0][0] = X.mal[i][0] - (X.mal[i-1][0] + cft_itv_lmt)
                elif targt_itv < cft_itv_lmt:
                    X.craft[i][0][0] = cft_itv_lmt
            elif round(X.mal[i][1]) > 1:  # 当前的mal包有超过1个cft包时
                for j in range(int(round(X.mal[i][1]))):
                    if j==0:  # 对于第一个craft包
                        if X.mal[i][0] - targt_itv < X.mal[i-1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.mal[i][0] - (X.mal[i-1][0] + cft_itv_lmt)
                        elif targt_itv < X.craft[i][j+1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j+1][0] + cft_itv_lmt
                    elif j==round(X.mal[i][1])-1:  # 对于最后一个craft包
                        if targt_itv > X.craft[i][j-1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j-1][0] - cft_itv_lmt
                        elif targt_itv < cft_itv_lmt:
                            X.craft[i][j][0] = cft_itv_lmt
                    else:  # 对于中间的craft包
                        if targt_itv > X.craft[i][j-1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j-1][0] - cft_itv_lmt
                        elif targt_itv < X.craft[i][j+1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j+1][0] + cft_itv_lmt

    # craft中`协议层数`和`数据长度`的范围规定
    # proto_max_lmt 是传进来的参数
    proto_min_lmt = 1.
    data_max_lmt = [np.nan,1500.,1480.,1460.]
    data_min_lmt = 0.
    # 更新craft中的`协议层数`和`数据长度`
    for i in range(grp_size):
        for j in range(int(round(X.mal[i][1]))):
            # 更新`协议层数`并判断范围
            if X.craft[i][j][1] < proto_min_lmt:
                X.craft[i][j][1] = proto_min_lmt
            elif X.craft[i][j][1] > proto_max_lmt[i]:
                X.craft[i][j][1] = proto_max_lmt[i]
            # 更新`数据长度`并判断范围
            X.craft[i][j][2] += V.craft[i][j][2]
            if X.craft[i][j][2] < data_min_lmt:
                X.craft[i][j][2] = data_min_lmt
            elif X.craft[i][j][2] > data_max_lmt[int(round(X.craft[i][j][1]))]:
                X.craft[i][j][2] = data_max_lmt[int(round(X.craft[i][j][1]))]

    return X

