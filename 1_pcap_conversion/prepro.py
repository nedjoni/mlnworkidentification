import os
import time
from scapy.all import *
#from pcapng.scanner import FileScanner
import numpy as np
import os
import multiprocessing as mp
import pickle as pk
from utils import *
    
data_dir = './data'

def gen_todo_list(directory, check = None):
    files = os.listdir(directory)
    todo_list = []
    for f in files:
        fullpath = os.path.join(directory, f)
        if os.path.isfile(fullpath):
            if check is not None:
                if check(f):
                    todo_list.append(fullpath)
            else:
                todo_list.append(fullpath)
    return todo_list

def mask_ip(packet):
    if IP in packet:
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'

    return packet

def pad_udp(packet):
    # get layers after udp
    layer_after = packet[UDP].payload.copy()

    # build a padding layer
    pad = Padding()
    pad.load = '\x00' * 12

    layer_before = packet.copy()
    layer_before[UDP].remove_payload()
    packet = layer_before / pad / layer_after

    return packet

def should_omit_packet(packet):
    # SYN, ACK or FIN flags set to 1 and no payload
    if TCP in packet and (packet.flags & 0x13):
        # not payload or contains only padding
        layers = packet[TCP].payload.layers()
        if not layers or (Padding in layers and len(layers) == 1):
            return True

    # DNS segment
    if DNS in packet:
        return True

    return False


def pkts2X(pkts):
    X = []
    #lens = []
    for p in pkts:

        if should_omit_packet(p):
            pass
        elif (TCP in p or UDP in p):
            #===================================
            # step 1 : mask ip adresses
            #===================================
            p = mask_ip(p)
            #===================================
            # step 2 : pad 0 to UDP Header
            #===================================
            if UDP in p:
                p = pad_udp(p)
            #===================================
            # step 3 : remove Ether Header,
            #          convert to numpy uint8
            #===================================
            r = raw(p)[14:]
            r = np.frombuffer(r, dtype = np.uint8)
            if (len(r) > 1500):
                pass
            else:
                X.append(r)
        else:
            pass
    return X

def get_data_by_file(filename):
    packet = rdpcap(filename)
    X = pkts2X(packet)
    # save X to npy and delete the original pcap (it's too large).
    return X

def task(filename):
    global dict_name2label
    global counter
    head, tail = os.path.split(filename)
    cond1 = os.path.isfile(os.path.join('data', tail+'.pickle'))
    # applications that are not on the list or already processed
    if (cond1 and (tail in dict_name2label) == False):
        with lock:
            counter.value += 1        
        print('[{}] {}'.format(counter, filename))
        return '#ALREADY#'
    X = get_data_by_file(filename)
    if (not cond1 and (tail in dict_name2label) == True):
        y = [dict_name2label[tail]] * len(X)
        with open(os.path.join('data', tail+'.pickle'), 'wb') as f:
            pk.dump((X, y), f)
    
    with lock:
        counter.value += 1
    print('[{}] {}'.format(counter, filename))
    return 'Done'



#=========================================
# mp init
#=========================================
lock = mp.Lock()
counter = mp.Value('i', 0)

if __name__ == '__main__':

    try:
        os.makedirs(data_dir)    
        print("Directory " , data_dir ,  " Created ")
    except FileExistsError:
        print("Directory " , data_dir ,  " already exists")  

    cpus = mp.cpu_count()//2
    pool = mp.Pool(processes=cpus)

    todo_list = gen_todo_list('./PCAP')

    #todo_list = todo_list[:3]

    total_number = len(todo_list)

    done_list = []

    res = pool.map(task, todo_list)

    print(len(res))
