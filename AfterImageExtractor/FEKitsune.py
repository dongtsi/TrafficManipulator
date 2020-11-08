from AfterImageExtractor.FeatureExtractor import *

STOP_FLAG = 999999999.
# MIT License
#
# Copyright (c) 2018 Yisroel mirsky
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


class Kitsune:
    #def __init__(self,file_path,limit,max_autoencoder_size=10,FM_grace_period=None,AD_grace_period=10000,learning_rate=0.1,hidden_ratio=0.75,):
    def __init__(self, file_path, limit, roll_back=False):
        #init packet feature extractor (AfterImage)
        self.FE = FE(file_path,limit,roll_back)
        self.roll_back = roll_back

    def proc_next_packet(self):

        # create feature vector
        x = self.FE.get_next_vector()
        if len(x) == 0:
            if self.roll_back:
                self.FE.nstat.RollBack()
            return [STOP_FLAG,STOP_FLAG] #Error or no packets left

        return x

    def change_path(self,new_path):
        self.FE.path = new_path

        self.FE.parse_type = None  # unknown
        self.FE.curPacketIndx = 0
        self.FE.tsvin = None  # used for parsing TSV file
        self.FE.scapyin = None  # used for parsing pcap with scapy

        ### Prep pcap ##
        self.FE.__prep__()


