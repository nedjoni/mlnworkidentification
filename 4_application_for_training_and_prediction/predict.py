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

# Main thread worker, this is where most of the program is done
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

        self.statusLabel.setText("Creating empty folders.")
        create_folder(folders)
        sleep(1)

        self.statusLabel.setText("Deleting content of the folders.")
        clean_folder(folders)
        sleep(1)

        # NFStream recognition and preprocessing of .pcap files
        ndpi_prepro(self)

        # Prediction
        self.statusLabel.setText("Preparing packets for prediction...")
        sleep(1)
        x_test, y_test = load_data(self, 'prediction')

        # Checking if there are no packets for prediction
        if x_test == None or y_test == None:
            self.statusLabel.setText("There is not enough packets for prediction. Choose another .pcap file")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')
            finished = pyqtSignal()
        else:
            # formating arrays in according to dimensions of required space, and formating of variable type (for numpy)
            x_cnn_test = np.expand_dims(x_test, axis=2).astype(np.float32)
            x_mlp_sae_test =  np.array(x_test).astype(np.float32)

            # sorted list of classes
            lista=[]
            [lista.append(x) for x in self.dict_name2label.values() if x not in lista]
            lista.sort()

            all_labels = []
            for value in self.dict_name2label.values():  
                all_labels.append(value)

            # one-hot-encoding of application names
            encoder = LabelEncoder()
            encoder.fit(all_labels)
            class_labels = encoder.classes_

            # number of classes in models
            nb_classes = len(class_labels)

            # number of tested samples
            test_count = [y_test.count(i) for i in range(len(class_labels)) ]

            encoded_y_test = encoder.transform(y_test)
            y_test = np_utils.to_categorical(encoded_y_test, num_classes = nb_classes)

            in_classes = [item for item in range(0, nb_classes)] # lista of label indices

            self.statusLabel.setText("Loading CNN model...")
            cnn_model = load_model('./models/cnn_model.h5')
            print("CNN model.")
            cnn_model.summary()

            self.statusLabel.setText("Loading SAE model...")
            sae_model = load_model('./models/sae_model.h5')
            print("SAE model.")
            sae_model.summary()

            self.statusLabel.setText("Loading MLP model...")
            mlp_model = load_model('./models/mlp_model.h5')
            print("MLP model.")
            mlp_model.summary()

            self.statusLabel.setText("Calculating models performances...")

            cnn_preds = cnn_model.predict(x_cnn_test, batch_size=32,  verbose=0)
            sae_preds = sae_model.predict(x_mlp_sae_test, batch_size=32,  verbose=0)
            mlp_preds = mlp_model.predict(x_mlp_sae_test, batch_size=32,  verbose=0)

            # true sample labels
            y_true_labels = [np.argmax(t) for t in y_test]

            # predicted sample labels
            y_cnn_preds_labels = [np.argmax(t) for t in cnn_preds]
            y_sae_preds_labels = [np.argmax(t) for t in sae_preds]
            y_mlp_preds_labels = [np.argmax(t) for t in mlp_preds]

            # number of tested samples
            test_count = [y_true_labels.count(i) for i in range(len(class_labels)) ]

            # creating formula for number of samples per indices
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

            # normalisation of values, easier way to plot chart in percents
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
            self.tabela.setHorizontalHeaderLabels(["Aplication", "CNN", "MLP", "SAE", "Total"])
            self.tabela.resizeColumnsToContents()
            self.tabela.resizeRowsToContents()

            # Pretty tabela
            a = PrettyTable(["", "Aplication", "CNN", "MLP", "SAE", "Total"])
            # Poravnanje u tabeli
            a.align[""] = "r"
            a.align["Aplication"] = "l"
            a.align["CNN"] = "r"
            a.align["MLP"] = "r"
            a.align["SAE"] = "r"
            a.align["Total"] = "r"
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

            # Ploting chart
            self.figure.clear()

            ax = self.figure.add_subplot(111)

            # Horizontal Bar Plot
            barHeight = 0.25
            barWidth = 0.25

            # Setting position of Bars on x axis
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
                    edgecolor ='grey', label ='No of samples')
             
            # Removing outside edges of the chart
            for s in ['top', 'bottom', 'left', 'right']:
                ax.spines[s].set_visible(False)
              
            # Adding space between axis and labels
            ax.xaxis.set_tick_params(pad = 5, labelsize = 8)
            ax.yaxis.set_tick_params(pad = 10, labelsize = 8)
             
            # Adding edge of x i y axis
            ax.grid(visible = True, color ='grey',
                    linestyle ='-.', linewidth = 0.5,
                    alpha = 0.2)
             
            # Showing values on the top
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

# User interface for file selection
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
        self.statusLabel.setText("You have to choose the file, and then start the prediction...")
        
        # Defining the table
        self.tabela = self.findChild(QTableWidget, "tabelaWidget")

        # Defining of the interface for a chart
        self.layout = self.findChild(QVBoxLayout, "grafikonLayout")
        self.figure = plt.figure(figsize = (5, 25))
        self.figure.subplots_adjust(left=0.407,right=0.970,
                    bottom=0.091,top=0.977,
                    hspace=0.2,wspace=0.2)
        self.canvas = FigureCanvas(self.figure)
        self.layout.addWidget(NavigationToolbar(self.canvas, self))
        self.layout.addWidget(self.canvas)

        # Defining of button's actions 
        self.ucitavanje.clicked.connect(self.otvaranje)
        self.pokretanje.clicked.connect(self.predikcija)
        
        # Showing application
        self.show()


    # Opening dialog for .pcap file selection 
    def otvaranje(self):
        clean_t()
        self.statusLabel.setStyleSheet('')

        # Dialog for file opening
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "PCAP files (*.pcap)")

        # Showing file name and enabling next button
        if fname:
            self.putanjaLabel.setText(str(fname))
            self.pokretanje.setDisabled(False)


    # Function which calls prediction worker thread       
    def predikcija(self):
        clean_t()
        self.worker = MainThread(self.putanjaLabel.text(), self.statusLabel, self.tabela, self.figure, self.canvas)
        self.worker.finished.connect(self.worker.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()


# Application identification
app = QApplication(sys.argv)
UIWindow = UI()


# qss file opening
styleFile = open("./Utilities/Integrid.qss",'r')
with styleFile:
    qss = styleFile.read()
    app.setStyleSheet(qss)


# Executing application
app.exec()