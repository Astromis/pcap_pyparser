from __future__ import division
from layers import *
from pcap_reader import *
from functional import *
from TimeProfiler import *
import pandas as pd
import numpy as np
import os
import argparse


def file2filter(f):
    return f.read().split()

def main(args):
    f1 = open(args.output, 'w')
    f = open(args.input,'r+b')
    filt = file2filter(open(args.filters,'r'))
    table_ = {i:set() for i in filt}
    #creating table. 
    for p in packet_generator(f):
        for s in filt:
            if p["transport_lay"]['data'].find(s) != -1:
                table_[s].add("%s-%s" % (p['ip_lay']['ip_src'], p['ip_lay']['ip_src']))
    #writing table into file
    for i in table_:
        f1.write(i + ": ")
        for j in table_[i]:
            f1.write(j + ' ')
        f1.write('\n')
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, help="input pcap file")
    parser.add_argument("output", type=str, help = "output file")
    parser.add_argument("filters", type=str,help="file with key-strings in a space")
    args = parser.parse_args()
    main(args)



    
