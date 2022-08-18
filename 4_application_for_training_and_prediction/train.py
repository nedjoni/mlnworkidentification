from PyQt6 import QtGui, uic
from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QFileDialog, QVBoxLayout, QTextEdit, QCheckBox, QTreeWidget, QTreeWidgetItem
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal, QUrl
import sip
import sys
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # or any {'0', '1', '2'}
from os import path
from datetime import datetime
import subprocess
from time import sleep
from nfstream import NFStreamer
import subprocess
import numpy as np
import pandas as pd
np.random.seed(210)
from tensorflow import keras
from keras.utils import np_utils
from keras.callbacks import ModelCheckpoint, TensorBoard, EarlyStopping
from sklearn.preprocessing import LabelEncoder
#from matplotlib.backends.qt_compat import QtWidgets
from Utilities.utils import *
import warnings
warnings.filterwarnings("ignore", category=np.VisibleDeprecationWarning) 


clean_t()


# QObject klasa za strimovanje ouputa terminala u QTextEdit
class Stream(QObject):
    newText = pyqtSignal(str)

    def write(self, text):
        self.newText.emit(str(text))

    # flush funkcija za sys.stdout
    def flush(self):
        pass


# Thread klasa za proceduru predobrade odabranog fajla
class PreprocessingThread(QThread):
    finished = pyqtSignal()
    def __init__(self, filepath, label, dict_name2label):
        QThread.__init__(self)
        self.filepath = filepath
        self.statusLabel = label
        self.dict_name2label = dict_name2label

    def run(self):
        # NFStream priprema draft liste za aplikacije
        ndpi_dict(self)

        # NFStream prepoznavanje i predobrada .pcap fajlova
        ndpi_prepro(self)

        print(self.dict_name2label)
        self.finished.emit()


# Thread klasa za kreiranje liste aplikacija za klasifikaciju
class LabelingThread(QThread):
    finished = pyqtSignal()
    def __init__(self, filepath, statusLabel, dict_name2label, counts):
        QThread.__init__(self)
        self.filepath = filepath
        self.statusLabel = statusLabel
        self.dict_name2label = dict_name2label
        self.counts = counts

    def run(self):
        # Konacno filterisanje i kreiranje liste aplikacija za klasifikaciju
        ## Bice odabrane samo one aplikacije koje su prosle preprocessing
        ## i imaju minimalno definisani broj paketa
        self.statusLabel.setText("Konačno filterisanje aplikacija za klasifikaciju")
        sleep(1)

        applications, packets = count_data(self)

        for i, app in enumerate(applications):
            self.counts[app] = packets[i]
        self.statusLabel.setText("Brojanje paketa za pronadjene aplikacije je zavrseno.")
        
        self.finished.emit()


# Thread klasa za treniranje modela
class TrainingThread(QThread):
    finished = pyqtSignal()
    def __init__(self, filepath, statusLabel, dict_name2label):
        QThread.__init__(self)
        self.filepath = filepath
        self.statusLabel = statusLabel
        self.dict_name2label = dict_name2label

    def run(self):
        # Odavde počinje proces treniranja
        ## Podaci će u procesu treniranja biti prilagođeni različitim modelima

        # učitavanje podataka
        x_train, y_train, x_val, y_val = load_data(self, 'training')

        # formatiranje nizova u skladu sa dimenzijama zahtjevanog prostora, i formatiranje tipa varijable (za numpy)
        x_cnn = np.expand_dims(x_train, axis=2).astype(np.float32)
        x_val_cnn = np.expand_dims(x_val, axis=2).astype(np.float32)
        x_mlp_sae = np.array(x_train).astype(np.float32)
        x_val_mlp_sae = np.array(x_val).astype(np.float32)

        # one-hot-encoding imena aplikacija
        encoder = LabelEncoder()
        encoder.fit(y_train)
        class_labels = encoder.classes_

        # broj klasa u modelima
        self.nb_classes = len(class_labels)

        encoded_y_train = encoder.transform(y_train)
        y_train = np_utils.to_categorical(encoded_y_train)
        encoded_y_val = encoder.transform(y_val)
        y_val = np_utils.to_categorical(encoded_y_val)

        # Definisanje i treniranje model masinskog ucenja
        batch_size = 32
        nb_epochs = 20

        def compiled_model(uncompiled_model):
            model = uncompiled_model
            model.summary()
            model.compile(
                optimizer = keras.optimizers.Adam(learning_rate=0.0001),
                loss = "categorical_crossentropy",
                metrics = ["accuracy"],
                run_eagerly = "true",
            )
            return model

        # EarlyStopping je postavljen kako bi se eliminisalo nepotrebno vrijeme dugog treniranja
        es = EarlyStopping(monitor='val_loss', mode='min', verbose=1, patience=5)
        def ModelCheck(saved_model_file):
            checkpoint = ModelCheckpoint(saved_model_file, monitor='val_loss', save_best_only=True, verbose=1)
            return checkpoint

        ## prvo se trenira CNN model
        print("Treniranje CNN modela...\n")
        self.statusLabel.setText("Treniranje CNN modela...")

        model = compiled_model(cnn_model(self))

        # lokacija za čuvanje CNN modela
        saved_model_file = 'models/cnn_model.h5'.format('conv1d-cnn')

        # Keeping model in control points where function loss improves
        # Čuvanje modela u tačkama gdje se funkcija gubitaka poboljšava
        fit_history = model.fit(x_cnn, y_train, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_val_cnn,y_val), callbacks=[ModelCheck(saved_model_file), es], verbose=2)

        print("Treniranje CNN modela je zavrseno.\n")
        self.statusLabel.setText("Treniranje CNN modela je zavrseno.")
        sleep(2)

        ## sledece se trenira MLP model
        print("Treniranje MLP modela...")
        self.statusLabel.setText("Treniranje MLP modela...")

        model = compiled_model(mlp_model(self))

        # lokacija za čuvanje MLP modela
        saved_model_file = 'models/mlp_model.h5'.format('mlp')

        # Čuvanje modela u tačkama gdje se funkcija gubitaka poboljšava
        fit_history = model.fit(x_mlp_sae, y_train, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_val_mlp_sae,y_val), callbacks=[ModelCheck(saved_model_file), es], verbose=2)

        print("Treniranje MLP modela je zavrseno.\n")
        self.statusLabel.setText("Treniranje MLP modela je zavrseno.")
        sleep(2)

        ## poslednji se trenira SAE model
        print("Treniranje SAE modela...")
        self.statusLabel.setText("Treniranje SAE modela...")

        model = compiled_model(sae_model(self))

        # lokacija za čuvanje SAE modela
        saved_model_file = 'models/sae_model.h5'.format('sae')

        # Čuvanje modela u tačkama gdje se funkcija gubitaka poboljšava
        fit_history = model.fit(x_mlp_sae, y_train, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_val_mlp_sae,y_val), callbacks=[ModelCheck(saved_model_file), es], verbose=2)

        print("Treniranje SAE modela je zavrseno.\n")
        self.statusLabel.setText("Treniranje SAE modela je zavrseno.")
        sleep(2)
        print("Modeli su spremni za predikciju.\n")

        self.statusLabel.setText("Treniranje modela je zavrseno.")
        self.statusLabel.setStyleSheet('color: rgb(170, 255, 0);')
    

# Korisnički interfejs sa odabir fajla
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        # Učitavanje ui fajla
        uic.loadUi("./Utilities/train_dialog.ui", self)

        # Define Widgets
        self.putanjaLabel = self.findChild(QLabel, "label")
        self.statusLabel = self.findChild(QLabel, "statusLabel")
        self.ucitavanje = self.findChild(QPushButton, "ucitavanjeButton")
        self.labelizacija = self.findChild(QPushButton, "aplikacijeButton")
        self.labelizacija.setDisabled(True)
        self.selektuj = self.findChild(QPushButton, "selektujButton")
        self.selektuj.setDisabled(True)
        self.deselektuj = self.findChild(QPushButton, "deselektujButton")
        self.deselektuj.setDisabled(True)
        self.treniraj = self.findChild(QPushButton, "treningButton")
        self.treniraj.setDisabled(True)
        self.statusLabel.setText("Potrebno je odabrati fajl, pa pokrenuti prepoznavanje aplikacija...")
        
        # Definisanje akcija dugmadi
        self.ucitavanje.clicked.connect(self.otvaranje)
        self.labelizacija.clicked.connect(self.preprocessing)
        self.treniraj.clicked.connect(self.odabrane_app)
        self.selektuj.clicked.connect(self.all_app)
        self.deselektuj.clicked.connect(self.none_app)

        # Definisanje okruženja aplikacije
        self.aplikacijeLayout = self.findChild(QVBoxLayout, "aplikacijeLayout")
        self.listA = None

        # Definisanje okruženja za ispis teksta sesije za treniranje
        self.treningText = self.findChild(QTextEdit, "textEdit")
        text=open('Utilities/Uputstvo.txt').read()
        self.treningText.setPlainText(text)

        # Definisanje varijabli
        self.dict_name2label = dict()
        self.counts = dict()
        self.checked_items = [] # lista za cekirane aplikacije      

        # Tekst sa terminala
        sys.stdout = Stream(newText=self.onUpdateText)  
        
        # Prikazivanje aplikacije
        self.show()


    # Otvaranje dijaloga za odabir .pcap fajla 
    def otvaranje(self):
        clean_t()
        # Dijalog za otvaranje fajla
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "PCAP files (*.pcap)")

        # Prikazivanje imena fajla i omogućavanje sledećeg dugmeta
        if fname:
            # Skrivanje dugmadi za kontrolu aplikacija
            self.selektuj.setDisabled(True)
            self.deselektuj.setDisabled(True)
            self.treniraj.setDisabled(True)
            # Ispis putanje i aktivacija sledećeg dugmeta
            self.putanjaLabel.setText(str(fname))
            self.labelizacija.setDisabled(False)


    # Predobrada fajlova
    def preprocessing(self):
        self.treningText.clear()
        clean_t()

        # Dugmad koja treba ugasiti
        self.labelizacija.setDisabled(True)

        self.filepath = self.putanjaLabel.text()

        self.worker = PreprocessingThread(self.filepath, self.statusLabel, self.dict_name2label)
        self.worker.finished.connect(self.odabir)
        self.worker.finished.connect(self.worker.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()
        

    # Funkcija koja kreira interfejs za odabir aplikacija za treniranje
    def odabir(self):
        self.treningText.clear()
        self.filter_liste()

        self.statusLabel.setStyleSheet('')

        # Otkrivanje dugmadi za kontrolu aplikacija
        self.selektuj.setDisabled(False)
        self.deselektuj.setDisabled(False)
        self.treniraj.setDisabled(False)

        self.statusLabel.setText("Prikazuju se pronađene aplikacije...")
        sleep(2)

        # QTreeWidget je fleksibilan za kreiranje liste aplikacija sa cekboksovima
        if not self.listA:
            self.listA = QTreeWidget()
            self.aplikacijeLayout.addWidget(self.listA)
            self.listA.setColumnCount(3)
            self.listA.setHeaderLabels(['Indeks','Aplikacija','Broj paketa'])
            self.listA.resizeColumnToContents(0)

        # Brisanje moguceg prethodnog sadrzaja QTreeWidget-a
        self.listA.clear()

        for key, val in self.counts.items():
            print("{} : {} paketa".format(key, val))
            item = QTreeWidgetItem()
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setData(1, Qt.ItemDataRole.UserRole, id(item))
            item.setText(1, key)
            item.setText(2, str(val))
            self.listA.addTopLevelItem(item)

        if len(self.counts) == 0:
            self.statusLabel.setText("Aplikacije u .pcap fajlu nemaju dovoljno paketa za treniranje. Odaberite drugi .pcap fajl.")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')
        else:
            self.statusLabel.setText("Odaberite aplikacije koje ce se koristiti za klasifikaciju i pokrenite trening modela")


    # Odabira sve ponudjene aplikacije
    def all_app(self):
        def recurse(parent_item):
            for i in range(parent_item.childCount()):
                item = parent_item.child(i)
                item.setCheckState(0, Qt.CheckState.Checked)

        recurse(self.listA.invisibleRootItem())


    # Uklanja sve ponudjene aplikacije iz odabira
    def none_app(self):
        def recurse(parent_item):
            for i in range(parent_item.childCount()):
                item = parent_item.child(i)
                item.setCheckState(0, Qt.CheckState.Unchecked)

        recurse(self.listA.invisibleRootItem())


    # Funkcija koja provjerava koje su aplikacije odabrane, i kreira konacnu listu aplikacija za treniranje
    def odabrane_app(self):
        # resetovanje potrebnih listi i interfejsa
        self.statusLabel.setStyleSheet('')
        self.checked_items = []
        self.dict_name2label = {}

        def recurse(parent_item):
            for i in range(parent_item.childCount()):
                item = parent_item.child(i)
                print (i, item.text(1))
                if item.checkState(0) == Qt.CheckState.Checked:
                    self.checked_items.append(item.text(1))
                        
                self.checked_items.sort()   
                        
        recurse(self.listA.invisibleRootItem())
        for app in self.checked_items:
            self.dict_name2label[app + '.pcap'] = app

        if len(self.checked_items) > 4:
            # Skrivanje dugmadi, u daljem procesu nisu vise potrebna
            self.ucitavanje.setDisabled(True)
            self.selektuj.setDisabled(True)
            self.deselektuj.setDisabled(True)
            self.treniraj.setDisabled(True)

            # Redraw liste aplikacija QTreeWidget-a
            self.listA.clear()
            self.listA.setColumnCount(2)
            self.listA.setHeaderLabels(['Indeks','Aplikacija','Broj paketa'])
            for i, app in enumerate(self.checked_items):
                item = QTreeWidgetItem()
                item.setData(0, Qt.ItemDataRole.UserRole, id(item))
                item.setText(0, str(i))
                item.setText(1, app)
                item.setText(2, str(self.counts[app]))
                self.listA.addTopLevelItem(item)
            self.listA.resizeColumnToContents(0)

            # Sledeći korak je treniranje modela
            self.statusLabel.setText("Treniranje modela...")
            self.trening()

        elif len(self.checked_items) == 0:
            self.statusLabel.setText("Nije odabrana nijedna aplikacija za treniranje")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')

        elif len(self.checked_items) <= 5:
            self.statusLabel.setText("Nije dabran dovoljan broj aplikacija za treniranje (Minimum je 5)")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')
            self.none_app()

        print('Odabrano je', len(self.checked_items), 'aplikacija.')
        print('checked_items: ',self.checked_items)


    # Funkcija koja poziva thread za trening modela
    def trening(self):

        # Konacna dict_name2label lista
        self.statusLabel.setText("Upis liste aplikacija u fajl za dalju upotrebu")
        with open('Utilities/apps.py','w') as data:
            data.write('# for app identification\n') 
            data.write('## created from file: {}\n'.format(self.filepath))
            data.write('## date created: {}\n'.format(datetime.now()))
            data.write('dict_name2label = {\n')
            for key, val in self.dict_name2label.items():
                data.write("\t'{}': '{}',\n".format(key, val))
            data.write('\t}')

        self.treningText.clear()
        self.worker = TrainingThread(self.filepath, self.statusLabel, self.dict_name2label)
        self.worker.finished.connect(self.reset_ui)
        self.worker.finished.connect(self.worker.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()


    # Funkcija koja poziva thread za filterisanje liste aplikacija
    def filter_liste(self):
        self.treningText.clear()
        self.worker = LabelingThread(self.filepath, self.statusLabel, self.dict_name2label, self.counts)
        self.worker.finished.connect(self.worker.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()


    # Resetuje elemente grafickog prikaza na osnovne vrijednosti
    def reset_ui(self):
        # Brisanje sadržaja
        self.listA.clear()

        # Otkrivanje dugmadi
        self.ucitavanje.setDisabled(False)
        # Skrivanje dugmadi
        self.selektuj.setDisabled(True)
        self.deselektuj.setDisabled(True)
        self.treniraj.setDisabled(True)

    
    # Za proceduru unosa teksta u QTextEdit
    def onUpdateText(self, text):
        """Write console output to text widget."""
        cursor = self.treningText.textCursor()
        #cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.treningText.setTextCursor(cursor)
        self.treningText.ensureCursorVisible()


    # Destructor metoda za sys.stdout
    def __del__(self):
        sys.stdout = sys.__stdout__


# Inicijalizacija aplikacije
app = QApplication(sys.argv)
UIWindow = UI()


# otvaranje qss fajla
styleFile = open("./Utilities/Integrid.qss",'r')
with styleFile:
    qss = styleFile.read()
    app.setStyleSheet(qss)


# Pokretanje aplikacije
app.exec()