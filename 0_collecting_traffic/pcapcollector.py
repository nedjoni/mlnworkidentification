from os import path
from nfstream import NFStreamer
import pandas as pd
import os
import subprocess
#import pyshark
#import time
from multiprocessing import Process # concurrency, paralelni procesi
from tqdm import trange
from time import sleep
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP

header = "Filtrating PCAP files"
pcap_input_dir = r'./INPCAP/' # folder for reading of PCAP files
pcap_dir = r'./PCAP/' # folder for saving of filtered PCAP packets
nf_dir = r'./DPI'
nf_path = nf_dir + "/base.csv" # folder for base of nfstream data
folders = [pcap_input_dir, nf_dir]

timeout = 60
packet_limit = 1000000000


# filtering inputs depending of the size of files/number of packets
def counting_dataset(pcap_dir):
    elim_list = []
    #startime = time.time()

    for pcap in os.scandir(pcap_dir):
        pcappath = pcap.path
        num = os.path.getsize(pcappath) # size of the packet
        #pcap = pyshark.FileCapture(pcappath)
        #pcap.load_packets()
        #num = len(pcap) # number of packets in file
        if(num > packet_limit):
            name = os.path.splitext(os.path.basename(pcappath))[0]
            elim_list.append(name)

    print ("No packet input for: " + str(elim_list).strip('[]')) 
    #endtime = time.time()
    #print(round(endtime - startime, 2))
    return elim_list

# cleaning the content of provided folders
def clean_folder(folders):
    for folder in folders:
        for filename in os.scandir(folder):
            path = filename.path
            os.remove(path) 

# providing time for pcap file naming
def pcaptime():
    ptime = subprocess.run(["date", '+"%Y.%m.%d.%H.%M.%S"'], capture_output=True) 
    return ptime

# header of the program
def header_m(header):
    os.system("clear") # for better transparency of the program
    print("\033[1;37;44m" + header + "\033[0;37m")

# inquiry for interface selection, which will be used to collect network traffic
def interfaces(header):
    header_m(header)
    allinterfaces = os.popen("ip -o link show | awk -F': ' '{print $2}'")
    allinterfaces = allinterfaces.read().split()

    print("List of interfaces:")
    for i in allinterfaces:
        print(str (allinterfaces.index(i)) + ": \033[1;32m" + i + "\033[0;37m")
 
    interface = input("Input number of interface for accepting incoming traffic: \n")
    interface = allinterfaces[int(interface)]
 
    return interface

# loader for pcap
def progress(): 
    for i in trange(timeout, desc="creating of pcap file", ascii = True):
        sleep(1) 

# creating PCAP file
def create_pcap(interface, name_pcap, timeout): 
    subprocess.run(["dumpcap", "-a", "duration:" + str(timeout), "-i", interface, "-q", "-s", "65535", "-w", name_pcap], capture_output=True)

# nDPI base
def dpi(pcap_input_dir, nf_path):
    ## DPI conversion to CSV
    for filename in os.scandir(pcap_input_dir):
        flows_rows_count = NFStreamer(source= filename.path).to_csv(path=nf_path)
 
    ## sorting from CSV file
    if (path.exists(nf_path) and os.stat(nf_path).st_size>0):
        df = pd.read_csv(nf_path, header=0, sep=',')
        data_index = df.columns.tolist()
        data_array = df.values
 
        x_nf, y_nf = [],[]
        for data in data_array:
            ### ip adressses
            src_ip = str(data[data_index.index("src_ip")])
            src_port = str(data[data_index.index("src_port")])
            dst_ip = str(data[data_index.index("dst_ip")])
            dst_port = str(data[data_index.index("dst_port")])
            app_name = str(data[data_index.index("application_name")])
 
            
            ### generating packet names
            #### IP and ports
            x_nf.append(src_ip + "-" + src_port + "--" + dst_ip + "-" + dst_port)
            #### protocol names
            y_nf.append(app_name)
 
        return x_nf, y_nf
    else:
        print("Empty PCAP file")
        return None, None

# using scapy to define packets IP and port
def ip_port(packet):
 
    if IP in packet:
        src_ip = str(packet[IP].src)
        dst_ip = str(packet[IP].dst)
    else:
        return None
    
    if TCP in packet:
        src_port = str(packet[TCP].sport)
        dst_port = str(packet[TCP].dport)
    elif UDP in packet:
        src_port = str(packet[UDP].sport)
        dst_port = str(packet[UDP].dport)
    else:
        return None
    return src_ip + "-" + src_port + "--" + dst_ip + "-" + dst_port

# rdcap conversion
def read_pcap(path):
    packets = rdpcap(str(path))
    return packets

# pcap input
def write(protocol, packet, elim_list):
    label_pcap = str(pcap_dir + protocol + '.pcap')
    if protocol not in elim_list:
        wrpcap(label_pcap, packet, append=True) # packets are added to the end of the pcap file

# division of PCAP files with nfstream application_name
def pcap_division(pcap_input_dir, elim_list):
    for filename in os.scandir(pcap_input_dir):
        for i, packet in enumerate(read_pcap(filename.path)):
            x_p = ip_port(packet)
            if(x_p != None and x_p in x_nf):
                protokol = y_nf[x_nf.index(x_p)]
                write(protokol, packet, elim_list)

interface = interfaces(header)
 
while True:
    header_m(header)
    clean_folder(folders)
    elim_list = counting_dataset(pcap_dir)
 
    time_pcap = str(pcaptime().stdout)[3:22] # formating date
    name_pcap = str(pcap_input_dir + interface + '-' + time_pcap + '.pcap')
    print("\033[1;32m" + timee_pcap + "\033[0;37m")
 
    Process(target=progress).start()
    Process(target=create_pcap(interface, name_pcap, timeout)).start() 
 
    x_nf, y_nf = dpi(pcap_input_dir, nf_path)
    print("NFstream transformation is finished")
    pcap_division(pcap_input_dir,elim_list)
    print("Packets are filtered and sorted")
    sleep(1)
