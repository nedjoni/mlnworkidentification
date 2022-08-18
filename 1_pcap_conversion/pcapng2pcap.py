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


# converting pcapng to pcap
for filename in os.scandir(pcap_input_dir):
    if filename.name.endswith(".pcapng"):
        print(filename.name, "to",filename.name.split(".pcapng")[0] +'.pcap')
        if os.name == 'nt':
        	subprocess.run(['C://Program Files//Wireshark//tshark', '-F', 'pcap', '-r', pcap_input_dir + filename.name, '-w', pcap_input_dir + (filename.name.split(".pcapng")[0] +'.pcap')])
        else:
        	subprocess.run(['tshark', '-F', 'pcap', '-r', pcap_input_dir + filename.name, '-w', pcap_input_dir + (filename.name.split(".pcapng")[0] +'.pcap')])

print("pcapng conversion is finished.")