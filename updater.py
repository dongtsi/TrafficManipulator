import numpy as np
from utils import Unit

D = 10000
DD = 1000


def generate_V(X, best_X, grp_size, max_cft_pkt):

    V = Unit(grp_size, max_cft_pkt)

    V.mal = best_X.mal - X.mal

    for i in range(grp_size):
        for j in range(int(round(X.mal[i][1]))):
            V.craft[i][j] = best_X.craft[i][j] - X.craft[i][j]

    return V


def update_X(X, V, grp_size, max_cft_pkt, last_end_time, groupList,
             max_time_extend, proto_max_lmt):

    last_end_time = float(last_end_time)

    max_mal_itv = (float(groupList[-1].time) -
                   last_end_time) * (max_time_extend + 1)

    mal_itv_lmt = max_mal_itv / D

    # mal_itv_lmt = 0

    for i in range(grp_size):
        targt_time = X.mal[i][0] + V.mal[i][0]
        if i == 0:
            if targt_time < last_end_time + mal_itv_lmt:
                X.mal[i][0] = last_end_time + mal_itv_lmt
            elif grp_size > 1:
                if targt_time > X.mal[i + 1][0] - mal_itv_lmt:
                    X.mal[i][0] = X.mal[i + 1][0] - mal_itv_lmt
                else:
                    X.mal[i][0] = targt_time
            else:
                X.mal[i][0] = targt_time
        elif i == grp_size - 1:
            if targt_time < X.mal[i - 1][0] + mal_itv_lmt:
                X.mal[i][0] = X.mal[i - 1][0] + mal_itv_lmt
            elif targt_time > (last_end_time + max_mal_itv) - mal_itv_lmt:
                X.mal[i][0] = (last_end_time + max_mal_itv) - mal_itv_lmt
            else:
                X.mal[i][0] = targt_time
        else:
            if targt_time < X.mal[i - 1][0] + mal_itv_lmt:
                X.mal[i][0] = X.mal[i - 1][0] + mal_itv_lmt
            elif targt_time > X.mal[i + 1][0] - mal_itv_lmt:
                X.mal[i][0] = X.mal[i + 1][0] - mal_itv_lmt
            else:
                X.mal[i][0] = targt_time

    for i in range(grp_size):
        if V.mal[i][1] < 0:
            X.mal[i][1] += V.mal[i][1]
            if X.mal[i][1] < 0:
                X.mal[i][1] = 0.
        else:
            if X.mal[i][1] + V.mal[i][1] > max_cft_pkt:
                ics_cft_num = max_cft_pkt - round(X.mal[i][1])
                targt_cft_num = max_cft_pkt
            else:
                ics_cft_num = round(X.mal[i][1] + V.mal[i][1]) - round(
                    X.mal[i][1])
                targt_cft_num = X.mal[i][1] + V.mal[i][1]

            for j in range(int(ics_cft_num)):
                if round(X.mal[i][1]) == 0:
                    if i == 0:
                        itv = X.mal[i][0] - last_end_time
                    else:
                        itv = X.mal[i][0] - X.mal[i - 1][0]
                else:
                    itv = X.craft[i][int(round(X.mal[i][1])) - 1][0]
                X.craft[i][int(round(X.mal[i][1])) +
                           j][0] = (itv / ics_cft_num) * (j + 1)

            X.mal[i][1] = targt_cft_num

    for i in range(grp_size):
        targt_itv = X.craft[i][0][0] + V.craft[i][0][0]

        if i == 0:
            cft_itv_lmt = (X.mal[i][0] - last_end_time) / DD

            if round(X.mal[i][1]) == 1:
                if X.mal[i][0] - targt_itv < last_end_time + cft_itv_lmt:
                    X.craft[i][0][0] = X.mal[i][0] - (last_end_time +
                                                      cft_itv_lmt)
                elif targt_itv < cft_itv_lmt:
                    X.craft[i][0][0] = cft_itv_lmt
            elif round(X.mal[i][1]) > 1:
                for j in range(int(round(X.mal[i][1]))):
                    if j == 0:
                        if X.mal[i][
                                0] - targt_itv < last_end_time + cft_itv_lmt:
                            X.craft[i][j][0] = X.mal[i][0] - (last_end_time +
                                                              cft_itv_lmt)
                        elif targt_itv < X.craft[i][j + 1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j +
                                                          1][0] + cft_itv_lmt
                    elif j == round(X.mal[i][1]) - 1:
                        if targt_itv > X.craft[i][j - 1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j -
                                                          1][0] - cft_itv_lmt
                        elif targt_itv < cft_itv_lmt:
                            X.craft[i][j][0] = cft_itv_lmt
                    else:
                        if targt_itv > X.craft[i][j - 1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j -
                                                          1][0] - cft_itv_lmt
                        elif targt_itv < X.craft[i][j + 1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j +
                                                          1][0] + cft_itv_lmt

        else:
            cft_itv_lmt = (X.mal[i][0] - X.mal[i - 1][0]) / DD
            if round(X.mal[i][1]) == 1:
                if X.mal[i][0] - targt_itv < X.mal[i - 1][0] + cft_itv_lmt:
                    X.craft[i][0][0] = X.mal[i][0] - (X.mal[i - 1][0] +
                                                      cft_itv_lmt)
                elif targt_itv < cft_itv_lmt:
                    X.craft[i][0][0] = cft_itv_lmt
            elif round(X.mal[i][1]) > 1:
                for j in range(int(round(X.mal[i][1]))):
                    if j == 0:
                        if X.mal[i][0] - targt_itv < X.mal[i -
                                                           1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.mal[i][0] - (X.mal[i - 1][0] +
                                                              cft_itv_lmt)
                        elif targt_itv < X.craft[i][j + 1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j +
                                                          1][0] + cft_itv_lmt
                    elif j == round(X.mal[i][1]) - 1:
                        if targt_itv > X.craft[i][j - 1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j -
                                                          1][0] - cft_itv_lmt
                        elif targt_itv < cft_itv_lmt:
                            X.craft[i][j][0] = cft_itv_lmt
                    else:
                        if targt_itv > X.craft[i][j - 1][0] - cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j -
                                                          1][0] - cft_itv_lmt
                        elif targt_itv < X.craft[i][j + 1][0] + cft_itv_lmt:
                            X.craft[i][j][0] = X.craft[i][j +
                                                          1][0] + cft_itv_lmt

    proto_min_lmt = 1.
    data_max_lmt = [np.nan, 1500., 1480., 1460.]
    data_min_lmt = 0.

    for i in range(grp_size):
        for j in range(int(round(X.mal[i][1]))):

            if X.craft[i][j][1] < proto_min_lmt:
                X.craft[i][j][1] = proto_min_lmt
            elif X.craft[i][j][1] > proto_max_lmt[i]:
                X.craft[i][j][1] = proto_max_lmt[i]

            X.craft[i][j][2] += V.craft[i][j][2]
            if X.craft[i][j][2] < data_min_lmt:
                X.craft[i][j][2] = data_min_lmt
            elif X.craft[i][j][2] > data_max_lmt[int(round(X.craft[i][j][1]))]:
                X.craft[i][j][2] = data_max_lmt[int(round(X.craft[i][j][1]))]

    return X
