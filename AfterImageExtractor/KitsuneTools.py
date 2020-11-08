import numpy as np

STOP_FLAG = 999999999.

# Input: K
def RunFE(
            K,
            origin_pos=None,
            output_file=".csv",
            show_info=False
          ):
    if show_info:
        print("@RunFE: Running Feature Extractor...")
    features = []
    all_features = []
    if origin_pos is None:
        while True:
            tmpx = K.proc_next_packet()
            if tmpx[0] == STOP_FLAG:
                break
            features.append(tmpx)
    else:
        i = 0
        j = 0
        while True:
            tmpx = K.proc_next_packet()
            if tmpx[0] == STOP_FLAG:
                if show_info:
                    print("@RunFE: Finish Feature Extractor...")
                break
            all_features.append(tmpx)
            if j < len(origin_pos) and i == origin_pos[j]:
                features.append(tmpx)
                j += 1
            i += 1
    if output_file != ".csv":
        np.savetxt(output_file, np.array(features)) #写入
        if show_info:
            print("@RunFE: Features are saved in .csv file!")
    return features,all_features

def safelyCopyNstat(ns,roll_back_flag):   # 2020.04
    ns.HT_jit.roll_back = roll_back_flag
    ns.HT_MI.roll_back = roll_back_flag
    ns.HT_H.roll_back = roll_back_flag
    ns.HT_Hp.roll_back = roll_back_flag
    return ns

# def RunKN(
#             K,
#             Feature,
#           ):
#     RMSEs = []
#     for x in Feature:
#         rmse = K.proc_next_packet(x)
#         if rmse == -1:
#             break
#         RMSEs.append(rmse)
#     return RMSEs