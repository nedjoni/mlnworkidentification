from PyQt6 import uic
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QFileDialog, QTableWidget, QTableWidgetItem, QVBoxLayout
from PyQt6.QtCore import QThread, Qt, pyqtSignal
#from pathlib import Path
import sys
import os
from os import path
import subprocess
import numpy as np
import pandas as pd
#np.random.seed(210)
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # or any {'0', '1', '2'}
import tensorflow as tf
from tensorflow import keras
#from keras import optimizers
from keras.utils import np_utils
from keras.models import Sequential, load_model
#from keras.layers import Dense, Dropout, Conv1D, MaxPooling1D, Flatten, Activation
#from keras.callbacks import ModelCheckpoint, TensorBoard
from sklearn.preprocessing import LabelEncoder
import seaborn as sn
import prettytable
from prettytable import PrettyTable
import matplotlib.pyplot as plt
import matplotlib.font_manager as font_manager
from matplotlib.backends.qt_compat import QtWidgets
from matplotlib.backends.backend_qtagg import FigureCanvas, NavigationToolbar2QT as NavigationToolbar
from matplotlib.figure import Figure
import subprocess
from time import sleep
from Utilities.apps import dict_name2label # za testiranje
from Utilities.utils import *


clean_t()

# Glavni thread worker, ovdje se obavlja glavni dio programa
class MainThread(QThread):
    finished = pyqtSignal()
    def __init__(self, filepath, label, tabela, grafikon, grafikonCanvas):
        QThread.__init__(self)
        self.dict_name2label = dict_name2label
        self.filepath = filepath
        self.statusLabel = label
        self.tabela = tabela
        self.figure = grafikon
        self.canvas = grafikonCanvas

    def run(self):

        self.statusLabel.setText("Kreiranje praznih foldera.")
        create_folder(folders)
        sleep(1)

        self.statusLabel.setText("Brisanje sadrzaja foldera.")
        clean_folder(folders)
        sleep(1)

        # NFStream prepoznavanje i predobrada .pcap fajlova
        ndpi_prepro(self)

        # predikcija
        self.statusLabel.setText("Priprema paketa za predikciju...")
        sleep(1)
        x_test, y_test = load_data(self, 'prediction')

        # Provjera u slučaju da nema paketa za predikciju
        if x_test == None or y_test == None:
            self.statusLabel.setText("Nema dovoljno paketa za predikciju. Odaberite drugi .pcap fajl")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')
            finished = pyqtSignal()
        else:
            # formatiranje nizova u skladu sa dimenzijama zahtjevanog prostora, i formatiranje tipa varijable (za numpy)
            x_cnn_test = np.expand_dims(x_test, axis=2).astype(np.float32)
            x_mlp_sae_test =  np.array(x_test).astype(np.float32)

            # sortirana lista klasa
            lista=[]
            [lista.append(x) for x in self.dict_name2label.values() if x not in lista]
            lista.sort()

            all_labels = []
            for value in self.dict_name2label.values():  
                all_labels.append(value)

            # one-hot-encoding imena aplikacija
            encoder = LabelEncoder()
            encoder.fit(all_labels)
            class_labels = encoder.classes_

            # broj klasa u modelima
            nb_classes = len(class_labels)

            # broj testiranih uzoraka
            test_count = [y_test.count(i) for i in range(len(class_labels)) ]

            encoded_y_test = encoder.transform(y_test)
            y_test = np_utils.to_categorical(encoded_y_test, num_classes = nb_classes)

            in_classes = [item for item in range(0, nb_classes)] # lista indeksa labela

            self.statusLabel.setText("Ucitavanje CNN modela...")
            cnn_model = load_model('./models/cnn_model.h5')
            print("CNN model.")
            cnn_model.summary()

            self.statusLabel.setText("Ucitavanje SAE modela...")
            sae_model = load_model('./models/sae_model.h5')
            print("SAE model.")
            sae_model.summary()

            self.statusLabel.setText("Ucitavanje MLP modela...")
            mlp_model = load_model('./models/mlp_model.h5')
            print("MLP model.")
            mlp_model.summary()

            self.statusLabel.setText("Racunanje performansi modela...")

            cnn_preds = cnn_model.predict(x_cnn_test, batch_size=32,  verbose=0)
            sae_preds = sae_model.predict(x_mlp_sae_test, batch_size=32,  verbose=0)
            mlp_preds = mlp_model.predict(x_mlp_sae_test, batch_size=32,  verbose=0)

            # pravi uzorci
            y_true_labels = [np.argmax(t) for t in y_test]

            # predicted samples
            y_cnn_preds_labels = [np.argmax(t) for t in cnn_preds]
            y_sae_preds_labels = [np.argmax(t) for t in sae_preds]
            y_mlp_preds_labels = [np.argmax(t) for t in mlp_preds]

            # broj testiranih uzoraka
            test_count = [y_true_labels.count(i) for i in range(len(class_labels)) ]

            # kreiranje formule za broja uzoraka po indeksima
            cnn_count = [ 0 for _ in range(len(class_labels)) ]
            sae_count = [ 0 for _ in range(len(class_labels)) ]
            mlp_count = [ 0 for _ in range(len(class_labels)) ]

            for i, j in zip(y_true_labels, y_cnn_preds_labels):
                if i == j:
                    cnn_count[i] = cnn_count[i] + 1

            for i, j in zip(y_true_labels, y_sae_preds_labels):
                if i == j:
                    sae_count[i] = sae_count[i] + 1

            for i, j in zip(y_true_labels, y_mlp_preds_labels):
                if i == j:
                    mlp_count[i] = mlp_count[i] + 1

            # normalizacija vrijednosti, lakši način za dobijanje grafikona u procentima
            test_normal = [ 0 for _ in range(len(class_labels)) ]
            cnn_normal = [ 0 for _ in range(len(class_labels)) ]
            sae_normal = [ 0 for _ in range(len(class_labels)) ]
            mlp_normal = [ 0 for _ in range(len(class_labels)) ]

            def normalize(i):
                if test_count[i] > 0:
                    raw = [test_count[i], cnn_count[i], sae_count[i], mlp_count[i]]
                    return [float("{:.2f}".format(float(i)/max(raw))) for i in raw]
                else:
                    return [0, 0, 0, 0]

            for r in range(len(class_labels)):
                test_normal[r], cnn_normal[r], sae_normal[r], mlp_normal[r] = normalize(r)
                
            print(test_normal)
            print(cnn_normal)
            print(sae_normal)
            print(mlp_normal)

            # Kreiranje tabele
            self.tabela.setColumnCount(5)
            self.tabela.setRowCount(len(lista))
            self.tabela.setHorizontalHeaderLabels(["Aplikacija", "CNN", "MLP", "SAE", "Ukupno"])
            self.tabela.resizeColumnsToContents()
            self.tabela.resizeRowsToContents()

            # Pretty tabela
            a = PrettyTable(["", "Aplikacije", "CNN", "MLP", "SAE", "Ukupno"])
            # Poravnanje u tabeli
            a.align[""] = "r"
            a.align["Aplikacije"] = "l"
            a.align["CNN"] = "r"
            a.align["MLP"] = "r"
            a.align["SAE"] = "r"
            a.align["Ukupno"] = "r"
            a.padding_width = 1

            for i, item in enumerate(class_labels):
                a.add_row([i, item, cnn_count[i], sae_count[i], mlp_count[i], test_count[i]])
                item_name = QTableWidgetItem(class_labels[i])
                item_cnn = QTableWidgetItem(str(cnn_count[i]))
                item_sae = QTableWidgetItem(str(sae_count[i]))
                item_mlp = QTableWidgetItem(str(mlp_count[i]))
                item_test = QTableWidgetItem(str(test_count[i]))

                # Elementi u tabeli su podešeni da budu poravnati na desno
                item_cnn.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                item_sae.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                item_mlp.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                item_test.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

                self.tabela.setItem(i, 0, item_name)
                self.tabela.setItem(i, 1, item_cnn)
                self.tabela.setItem(i, 2, item_sae)
                self.tabela.setItem(i, 3, item_mlp)
                self.tabela.setItem(i, 4, item_test)

            self.tabela.resizeColumnsToContents()
            self.tabela.resizeRowsToContents()

            print(a)

            # Crtanje grafikona
            self.figure.clear()

            ax = self.figure.add_subplot(111)

            # Horizontal Bar Plot
            barHeight = 0.25
            barWidth = 0.25

            # Postavljanje pozicije barova grafikona na X osi
            br1 = np.arange(len(class_labels))
            br2 = [y + barHeight for y in br1]
            br3 = [y + barHeight for y in br2]
            br4 = [y + barHeight for y in br3]

            ax.barh(br1, cnn_normal, color ='r', height = barHeight,
                    edgecolor ='grey', label ='CNN')
            ax.barh(br2, sae_normal, color ='g', height = barHeight,
                    edgecolor ='grey', label ='SAE')
            ax.barh(br3, mlp_normal, color ='y', height = barHeight,
                    edgecolor ='grey', label ='MLP')
            ax.barh(br4, test_normal, color ='b', height = barHeight,
                    edgecolor ='grey', label ='Broj uzoraka')
             
            # Uklanjanje sploljnih ivica grafikona
            for s in ['top', 'bottom', 'left', 'right']:
                ax.spines[s].set_visible(False)
              
            # Dodavanje prostora između osa i labela
            ax.xaxis.set_tick_params(pad = 5, labelsize = 8)
            ax.yaxis.set_tick_params(pad = 10, labelsize = 8)
             
            # Dodavanje ivica x i y ose
            ax.grid(visible = True, color ='grey',
                    linestyle ='-.', linewidth = 0.5,
                    alpha = 0.2)
             
            # Prikazivanje vrijednosti na vrhu
            ax.invert_yaxis()
             
            ax.set_ylabel('Aplikacija', fontweight ='bold', fontsize = 10)
            ax.set_xlabel('Predikcija (%)', fontweight ='bold', fontsize = 10)
            ax.yaxis.set_ticks([r + barWidth for r in range(len(class_labels))], class_labels)

            axfont = font_manager.FontProperties(style='normal', size=6)
            ax.legend(prop=axfont)
            ax.plot()
            self.canvas.draw()
            
            self.statusLabel.setText("Predikcija je zavrsena.")
            self.statusLabel.setStyleSheet('color: rgb(170, 255, 0);')

            self.finished.emit()

# Korisnički interfejs sa odabir fajla
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        # Load the ui file
        # Učitavanje ui fajlova
        uic.loadUi("./Utilities/predict_dialog.ui", self)

        # Define Widgets
        self.putanjaLabel = self.findChild(QLabel, "label")
        self.statusLabel = self.findChild(QLabel, "statusLabel")
        self.ucitavanje = self.findChild(QPushButton, "ucitavanjeButton")
        self.pokretanje = self.findChild(QPushButton, "pokretanjeButton")
        self.pokretanje.setDisabled(True)
        self.statusLabel.setText("Potrebno je odabrati fajl, pa pokrenuti predikciju...")
        
        # Definisanje tebele
        self.tabela = self.findChild(QTableWidget, "tabelaWidget")

        # Definisanje okruženja za grafikon
        self.layout = self.findChild(QVBoxLayout, "grafikonLayout")
        self.figure = plt.figure(figsize = (5, 25))
        self.figure.subplots_adjust(left=0.407,right=0.970,
                    bottom=0.091,top=0.977,
                    hspace=0.2,wspace=0.2)
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(NavigationToolbar(self.canvas, self))
        self.layout.addWidget(self.canvas)

        # Definisanje akcija dugmadi 
        self.ucitavanje.clicked.connect(self.otvaranje)
        self.pokretanje.clicked.connect(self.predikcija)
        
        # Prikazivanje aplikacije
        self.show()


    # Otvaranje dijaloga za odabir .pcap fajla 
    def otvaranje(self):
        clean_t()
        self.statusLabel.setStyleSheet('')

        # Dijalog za otvaranje fajla
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "PCAP files (*.pcap)")

        # Prikazivanje imena fajla i omogućavanje sledećeg dugmeta
        if fname:
            self.putanjaLabel.setText(str(fname))
            self.pokretanje.setDisabled(False)


    # Funkcija koja poziva thread za predikciju mrežnog saobraćaja       
    def predikcija(self):
        clean_t()
        self.worker = MainThread(self.putanjaLabel.text(), self.statusLabel, self.tabela, self.figure, self.canvas)
        self.worker.finished.connect(self.worker.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()


# Inicijalizacija aplikacije
app = QApplication(sys.argv)
UIWindow = UI()


# Otvaranje qss fajla
styleFile = open("./Utilities/Integrid.qss",'r')
with styleFile:
    qss = styleFile.read()
    app.setStyleSheet(qss)


# Pokretanje aplikacije
app.exec()