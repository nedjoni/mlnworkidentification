from os import path
from nfstream import NFStreamer
import pandas as pd
import os
import subprocess
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP

pcap_input_dir = r'./INPCAP/' # input pcap folder
nf_dir = r'./DPI'
nf_path = nf_dir + "/baza_" # nDPI base folder


# nDPI base
def dpi(pcap_input_dir, nf_path):
    ## saving bases to CSV
    for filename in os.scandir(pcap_input_dir):
        if filename.name.endswith(".pcap"):
            print(filename.name)
            flows_rows_count = NFStreamer(source= filename.path).to_csv(path=(nf_path + filename.name + ".csv"))

if __name__ == '__main__':
	dpi(pcap_input_dir, nf_path)
	print("NFstream transformation is finished.")