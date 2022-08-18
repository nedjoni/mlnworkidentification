import os
import platform
import time
import re # "Regular Expression"
import pandas as pd
from os import path
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # or any {'0', '1', '2'}
from nfstream import NFStreamer
from sklearn.preprocessing import LabelEncoder
import multiprocessing as mp
from time import sleep
import numpy as np
import pickle as pk
from keras.models import Sequential
from keras.layers import Dense, Dropout, Conv1D, MaxPooling1D, Flatten, Activation
from scapy.all import *
import warnings
warnings.filterwarnings("ignore", category=np.VisibleDeprecationWarning) 


# required folders
pcap_dir = r'./PCAP/' # folder za čuvanje filterisanih .pcap paketa
nf_dir = r'./DPI'
pickle_dir = r'./data/' # folder za .pickle fajlove
nf_path = nf_dir + "/base.csv" # folder za nfstream bazu podataka
folders = [pcap_dir, nf_dir, pickle_dir]


# Čišćenje terminala za bolju preglednost programa
def clean_t():
    if platform == "linux" or platform == "linux2":
        os.system("clear") 
    elif platform == "darwin":
        # OS X
        print('Nije implementirano')
    elif platform == "win32":
        # Windows
        os.system("cls")


# Provjera da li postoje potrebni folderi
def create_folder(folders):
    for folder in folders:
        try:
            os.makedirs(folder)    
            print("Folder" , folder ,  "je kreiran")
        except FileExistsError:
            print("Folder" , folder ,  "već postoji")  


# Čišćenje sadržaja predviđenih foldera
def clean_folder(folders):
    for folder in folders:
        for filename in os.scandir(folder):
            path = filename.path
            os.remove(path)


# Generisanje todo_list-e fajlova iz pickle foldera
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


# nDPI base
def dpi(nf_path):
    ## sortiranje iz .csv file
    if (path.exists(nf_path) and os.stat(nf_path).st_size>0):
        df = pd.read_csv(nf_path, header=0, sep=',')
        data_index = df.columns.tolist()
        data_array = df.values
        x_nf, y_nf = [],[]
        for data in data_array:
            ### ip adrese 
            src_ip = str(data[data_index.index("src_ip")])
            src_port = str(data[data_index.index("src_port")])
            dst_ip = str(data[data_index.index("dst_ip")])
            dst_port = str(data[data_index.index("dst_port")])
            app_name = str(data[data_index.index("application_name")])

            ### generisanje imena paketa
            #### IP i portovi
            x_nf.append(src_ip + "-" + src_port + "--" + dst_ip + "-" + dst_port)
            #### imena protokola
            y_nf.append(app_name)
        return x_nf, y_nf
    else:
        print("Empty PCAP file")
        return None, None


# Korišćenje scapy modula za definisanje paketa IP-ja i portova
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


# rdcap konverzija
def read_pcap(path):
    packets = rdpcap(str(path))
    return packets


# Upis .pcap fajlova
def write(aplikacije, lista):
    for n in range(len(lista)):
        l = len(aplikacije[n])
        if l > 0:
            print(lista[n], 'je pronadjen. Sadrži {} paketa. Čuvanje paketa...'.format(l))
            wrpcap(str(pcap_dir + lista[n] + '.pcap'), aplikacije[n], append=True)  # dodavanje paketa na kraj .pcap fajla


# Učitavanje podataka iz .pickle fajlova
def load(filename):
    with open(filename, 'rb') as f:
        try:
            data = pk.load(f)
        except EOFError:
            data = list()
    return data


# loading all files from pickle folder
# Učitavanje svih fajlova iz .pickle foldera
def load_data(self, operacija):
    # ovdje se definiše minimalni broj paketa po aplikaciji 
    max_data_nb = 1000
    train_rate = 0.75

    # todo_list se mora dodatno filterisati, kako bi bile obradjene samo odabrane aplikacije
    todo_list = gen_todo_list(pickle_dir)
    tmp_todo = []
    print("\nPickle todo lista:\n")
    for file in todo_list:
        if re.split(pickle_dir + "|.pickle", file)[1] in self.dict_name2label.keys():
            tmp_todo.append(file)
            print(file)
    todo_list = tmp_todo
    
    sleep(10)

    X = []
    y = []
    X_val = []
    y_val = []


    if operacija == 'training':
        if len(todo_list) == 0:
            return None, None, None, None
        else:
            for counter, filename in enumerate(todo_list):
                (tmpX, tmpy) = load(filename)
                if len(tmpX) > 0:
                    tmpX , tmpy = tmpX[:max_data_nb], tmpy[:max_data_nb]
                    tmpX = processX(tmpX)
                    train_num = int(len(tmpX) * train_rate)
                    X.extend(tmpX[:train_num])
                    y.extend(tmpy[:train_num])
                    X_val.extend(tmpX[train_num:])
                    y_val.extend(tmpy[train_num:])
                    print('\rUčitavanje... {}/{}'.format(counter+1,len(todo_list)), end = '')
            print('\r{} Podaci su učitani.               '.format(len(todo_list)))
            return X, y, X_val, y_val
        
    elif operacija == 'prediction':
        if len(todo_list) == 0:
            return None, None
        else:
            for counter, filename in enumerate(todo_list):
                (tmpX, tmpy) = load(filename)     
                if len(tmpX) > 0:
                    tmpX = processX(tmpX)
                    X.extend(tmpX)
                    y.extend(tmpy)
                    print('\rUčitavanje... {}/{}'.format(counter+1,len(todo_list)), end = '')
            print('\r{} \nPodaci su učitani.               '.format(len(todo_list)))
            return X, y


# brojanje paketa u .pickle fajlovima
def count_data(self):
    self.dict_name2label = dict()
    max_data_nb = 1000
    min_data_nb = 10
    todo_list = gen_todo_list(pickle_dir)
    applications = []
    packets = []

    for counter, filename in enumerate(todo_list):
        (tmpX, tmpy) = load(filename)
        tmpX , tmpy = tmpX[:max_data_nb], tmpy[:max_data_nb]  
        # ovdje se definiše minimalni broj paketa po aplikaciji  
        if len(tmpy) > min_data_nb:
            applications.append(tmpy[0])
            packets.append(len(tmpy))

    # paketi i aplikacije se moraju sortirati zajedno
    if len(applications) == 0:
        self.dict_name2label = dict()
        return applications, packets
    else:
        l = list(zip(applications, packets))
        l.sort()
        # 'unzip'
        applications, packets = zip(*l)
        for app in applications:
                self.dict_name2label[app + '.pcap'] = app
        return applications, packets


# Obrada podataka u payload-ima paketa
def processX(X):
    if True:
        X = np.array(X)
        lens = [len(x) for x in X] 
        maxlen = 1500
        tmpX = np.zeros((len(X), maxlen))
        mask = np.arange(maxlen) < np.array(lens)[:,None]
        tmpX[mask] = np.concatenate(X)
        return tmpX
    else:
        for i, x in enumerate(X):
            tmp_x = np.zeros((1500,))
            tmp_x[:len(x)] = x
            X[i] = tmp_x
        return X


# Brojanje nDPI detekcija
def ndpi_dict(self):
    self.statusLabel.setStyleSheet('')
    self.statusLabel.setText("Kreiranje praznih foldera.")
    create_folder(folders)
    sleep(1)

    self.statusLabel.setText("Brisanje sadrzaja foldera.")
    clean_folder(folders)
    sleep(1)

    self.statusLabel.setText("Pokretanje modula NFStream...")
    sleep(1)
    filename = os.path.basename(self.filepath)
    # podjela .pcap fajlova korišćenjem nfstream application_name
    if self.filepath.endswith(".pcap"):
        # sprječava otvaranje više prozora u QT mainUI funkciji
        subprocess.run(['python', 'Utilities/nfs.py', self.filepath, nf_path])

        self.statusLabel.setText("NFStream prepoznavanje je zavrseno.")
        sleep(1)
    
    self.statusLabel.setText("Kreiranje draft liste za pronadjene aplikacije...")
    df = pd.read_csv(nf_path, header=0, sep=',')
    encoder = LabelEncoder()
    encoder.fit(df['application_name'])
    # lista svih nDPI prepoznatih aplikacija
    apps = encoder.classes_
    # lista nDPI aplikacija koje nece biti razmatrane
    apps_blacklist = ['HTTP', 'TLS', 'QUIC', 'Unknown', 'DHCPV6']
    for app in apps:
        if app not in apps_blacklist and app.startswith('DNS') == False: # ovdje se eliminisu i DNS paketi
            self.dict_name2label[app + '.pcap'] = app
    self.statusLabel.setText("Kreiranje draft liste za pronadjene aplikacije je zavrseno.")
    sleep(1)


# obrada i labelovanje paketa sa nDPI
def ndpi_prepro(self):
    self.statusLabel.setStyleSheet('')

    self.statusLabel.setText("Pokretanje modula NFStream...")
    sleep(1)
    filename = os.path.basename(self.filepath)
    # podjela .pcap fajlova korišćenjem nfstream application_name
    if self.filepath.endswith(".pcap"):
        # sprječava otvaranje više prozora u QT mainUI funkciji
        subprocess.run(['python', 'Utilities/nfs.py', self.filepath, nf_path])

        self.statusLabel.setText("NFStream prepoznavanje zavrseno.")
        sleep(1)
        
        self.statusLabel.setText("Kreiranje .pcap fajlova sa nDPI labelama...")
        sleep(1)

        # sortirana lista klasa
        lista=[]
        [lista.append(x) for x in self.dict_name2label.values() if x not in lista]
        lista.sort()

        aplikacije = [ [] for _ in range(len(lista)) ]  # kreiranje prazne liste za aplikacije
        x_nf, y_nf = dpi(nf_path)

        for i, packet in enumerate(read_pcap(self.filepath)):
            x_p = ip_port(packet)
            if(x_p != None and x_p in x_nf and y_nf[x_nf.index(x_p)] in lista):
                # pretraga app indeksa
                app_index = lista.index(y_nf[x_nf.index(x_p)])
                aplikacije[app_index].append(packet)
        write(aplikacije, lista)
        self.statusLabel.setText("Obrada " + filename + " je zavrsena.")
        sleep(1)
        with open('Utilities/apps.py','w') as data:
            data.write('# for app identification\n') 
            data.write('## created from file {}\n'.format(self.filepath))
            data.write('## draft version for used for application filtering\n')
            data.write('dict_name2label = {\n')
            #for app in aplikacije:
            for key, val in self.dict_name2label.items():
                #if val == app:
                    data.write("\t'{}': '{}',\n".format(key, val))
            data.write('\t}')
    else:
        self.statusLabel.setText("Odabrani fajl nije u .pcap fajl formatu.")

    # predobrada .pcap fajlova
    self.statusLabel.setText("Predobrada .pcap fajlova...")
    subprocess.run(['python', 'Utilities/prepro.py'])
    self.statusLabel.setText("Predobrada je zavrsena.")
    sleep(1)


# definisanje CNN modela
def cnn_model(self):
    input_size = 1500
    dropout = 0.2

    # Build a model
    model = Sequential()
    model.add(Conv1D(60, 5, input_shape = (input_size,1), activation = 'relu'))
    model.add(Dropout(dropout))
    model.add(MaxPooling1D(2))
    model.add(Flatten())
    denses = [200, 100, 50]
    for dense in denses:
        model.add(Dense(dense, activation = 'relu'))
        model.add(Dropout(dropout))
    model.add(Dense(self.nb_classes, activation = 'softmax'))
    return model


# definisanje MLP modela
def mlp_model(self):
    input_size = 1500
    input_dense = 1500
    dropout = 0.2

    # Izrada modela
    model = Sequential()

    model.add(Dense(input_dense, batch_input_shape=(None, input_size), activation = 'relu'))
    model.add(Dropout(dropout))

    for x in range(0, 2):
        model.add(Dense(units=input_dense, activation = 'relu'))
        model.add(Dropout(dropout))

    model.add(Dense(self.nb_classes, activation = 'softmax'))
    return model


# definisanje SAE modela
def sae_model(self):
    input_size = 1500
    input_dense = 600
    denses = np.arange(1200, 0, -input_dense).tolist()
    dropout = 0.2

    # Izrada modela
    model = Sequential()

    # enkoder
    model.add(Dense(denses[0], batch_input_shape=(None, input_size), activation = 'relu'))
    model.add(Dropout(dropout))
    for i in denses[1:]:
        model.add(Dense(i, activation = 'relu'))
        model.add(Dropout(dropout))

    # dekoder
    denses.reverse()
    for i in denses[1:]:
        model.add(Dense(i, activation = 'relu'))
        model.add(Dropout(dropout))
    model.add(Dense(input_size, activation = 'relu'))
    model.add(Dropout(dropout))

    model.add(Dense(self.nb_classes, activation = 'softmax'))
    return model