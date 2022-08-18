from os import path
import pandas as pd
import numpy as np
import multiprocessing as mp
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from utils import dict_name2label

pcap_input_dir = r'./INPCAP/'  # input pcap folder
pcap_dir = r'./PCAP/' # output folder for filtered pcap files
nf_dir = r'./DPI'
nf_path = nf_dir + "/baza_" # nDPI base folder


# mp init
lock = mp.Lock()
counter = mp.Value('i', 0)

app_list = list(dict_name2label.values())
app_list.sort()

# nDPI base
def dpi(pcap_input_dir, nf_path):
    ## sorting from CSV file
    if (path.exists(nf_path) and os.stat(nf_path).st_size>0):
        df = pd.read_csv(nf_path, header=0, sep=',')
        data_index = df.columns.tolist()
        data_array = df.values

        x_nf, y_nf = [],[]
        for data in data_array:
            ### ip address 
            src_ip = str(data[data_index.index("src_ip")])
            src_port = str(data[data_index.index("src_port")])
            dst_ip = str(data[data_index.index("dst_ip")])
            dst_port = str(data[data_index.index("dst_port")])
            app_name = str(data[data_index.index("application_name")])

            
            ### packet name generating
            #### IP and ports
            x_nf.append(src_ip + "-" + src_port + "--" + dst_ip + "-" + dst_port)
            #### protocol names
            y_nf.append(app_name)

        return x_nf, y_nf
    else:
        print("Emppty PCAP file")
        return None, None

# defining ip and port packets with scapy
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

# writing pcap
def write(aplikacije):
    for n in range(len(app_list)):
        if len(aplikacije[n]) > 0:
            wrpcap(str(pcap_dir + app_list[n] + '.pcap'), aplikacije[n], append=True)  #append packets at the end of the pcap file

if __name__ == '__main__':

    cpus = mp.cpu_count()//2
    pool = mp.Pool(processes=cpus)

    # splitting pcap files using nfstream application_name
    for filename in os.scandir(pcap_input_dir):
        aplikacije = [ [] for _ in range(len(app_list)) ]  # creating empty list for applications, this method works great
        if filename.name.endswith(".pcap"):
            print(filename.name, "is processed")
            # possible error while base loading
            try:
                x_nf, y_nf = dpi(pcap_input_dir, nf_path + filename.name + ".csv")
                print("nDPI base for", filename.name, "is loaded")
                if not(path.exists(pcap_input_dir + filename.name + '_SUCCESS')):
                    for i, packet in enumerate(read_pcap(filename.path)):
                        x_p = ip_port(packet)
                        if(x_p != None and x_p in x_nf and y_nf[x_nf.index(x_p)] in app_list):
                            # trazenje indeksa aplikacije u nizu
                            app_index = app_list.index(y_nf[x_nf.index(x_p)])
                            aplikacije[app_index].append(packet)
                    # Ispisivanje paketa u PCAP format (merge sa postojecim PCAP fajlovima)
                    write(aplikacije)
                    with open(pcap_input_dir + filename.name + '_SUCCESS', "w") as f:
                        pass
                else:
                    print("File is already processed")
            except:
                with open(pcap_input_dir + filename.name + '_SUCCESS', "w") as f:
                    pass
            print("Processing of", filename.name, "is done")