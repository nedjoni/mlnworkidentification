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


# QObject class for output streaming from terminal in QTextEdit
class Stream(QObject):
    newText = pyqtSignal(str)

    def write(self, text):
        self.newText.emit(str(text))

    # flush funkction for sys.stdout
    def flush(self):
        pass


# Thread class for preprocessing procedure of the chosen file
class PreprocessingThread(QThread):
    finished = pyqtSignal()
    def __init__(self, filepath, label, dict_name2label):
        QThread.__init__(self)
        self.filepath = filepath
        self.statusLabel = label
        self.dict_name2label = dict_name2label

    def run(self):
        # NFStream preparing of drafti list for applications
        ndpi_dict(self)

        # NFStream recognition and preprocessing of .pcap files
        ndpi_prepro(self)

        print(self.dict_name2label)
        self.finished.emit()


# Thread class for creating of classification list for applications
class LabelingThread(QThread):
    finished = pyqtSignal()
    def __init__(self, filepath, statusLabel, dict_name2label, counts):
        QThread.__init__(self)
        self.filepath = filepath
        self.statusLabel = statusLabel
        self.dict_name2label = dict_name2label
        self.counts = counts

    def run(self):
        # Final filtering and creating of application list for classification
        ## Applications will be chosen only if they finished preprocessing process
        ## and have minimum of defined packages
        self.statusLabel.setText("Final filtering of application for classification")
        sleep(1)

        applications, packets = count_data(self)

        for i, app in enumerate(applications):
            self.counts[app] = packets[i]
        self.statusLabel.setText("Counting packets for detected applications is finished.")
        
        self.finished.emit()


# Thread class for model training
class TrainingThread(QThread):
    finished = pyqtSignal()
    def __init__(self, filepath, statusLabel, dict_name2label):
        QThread.__init__(self)
        self.filepath = filepath
        self.statusLabel = statusLabel
        self.dict_name2label = dict_name2label

    def run(self):
        # From here on begins process of training
        ## Data will be adapted for different models

        # data loading
        x_train, y_train, x_val, y_val = load_data(self, 'training')

        # formating arrays in according to dimensions of required space, and formating of variable type (for numpy)
        x_cnn = np.expand_dims(x_train, axis=2).astype(np.float32)
        x_val_cnn = np.expand_dims(x_val, axis=2).astype(np.float32)
        x_mlp_sae = np.array(x_train).astype(np.float32)
        x_val_mlp_sae = np.array(x_val).astype(np.float32)

        # one-hot-encoding of application names
        encoder = LabelEncoder()
        encoder.fit(y_train)
        class_labels = encoder.classes_

        # number of classes in models
        self.nb_classes = len(class_labels)

        encoded_y_train = encoder.transform(y_train)
        y_train = np_utils.to_categorical(encoded_y_train)
        encoded_y_val = encoder.transform(y_val)
        y_val = np_utils.to_categorical(encoded_y_val)

        # Defining and training of machine learning models
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

        # EarlyStopping is added to eliminate unecessary long timed training
        es = EarlyStopping(monitor='val_loss', mode='min', verbose=1, patience=5)
        def ModelCheck(saved_model_file):
            checkpoint = ModelCheckpoint(saved_model_file, monitor='val_loss', save_best_only=True, verbose=1)
            return checkpoint

        ## firstly, CNN model is trained
        print("Training of CNN model...\n")
        self.statusLabel.setText("Training of CNN model...")

        model = compiled_model(cnn_model(self))

        # location for saving CNN model
        saved_model_file = 'models/cnn_model.h5'.format('conv1d-cnn')

        # Keeping model in control points where function loss improves
        fit_history = model.fit(x_cnn, y_train, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_val_cnn,y_val), callbacks=[ModelCheck(saved_model_file), es], verbose=2)

        print("Training of CNN model is finished.\n")
        self.statusLabel.setText("Training of CNN model is finished.")
        sleep(2)

        ## next comes training of MLP model
        print("Training of MLP model...")
        self.statusLabel.setText("Training of MLP model...")

        model = compiled_model(mlp_model(self))

        # location for saving MLP model
        saved_model_file = 'models/mlp_model.h5'.format('mlp')

        # Keeping model in control points where function loss improves
        fit_history = model.fit(x_mlp_sae, y_train, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_val_mlp_sae,y_val), callbacks=[ModelCheck(saved_model_file), es], verbose=2)

        print("Training of MLP model is finished.\n")
        self.statusLabel.setText("Training of MLP model is finished.")
        sleep(2)

        ## SAE model is trained last
        print("Training of SAE model...")
        self.statusLabel.setText("Training of SAE model...")

        model = compiled_model(sae_model(self))

        # location for saving SAE model
        saved_model_file = 'models/sae_model.h5'.format('sae')

        # Keeping model in control points where function loss improves
        fit_history = model.fit(x_mlp_sae, y_train, epochs=nb_epochs, batch_size=batch_size, validation_data=(x_val_mlp_sae,y_val), callbacks=[ModelCheck(saved_model_file), es], verbose=2)

        print("Training of SAE model is finished.\n")
        self.statusLabel.setText("Training of SAE model is finished.")
        sleep(2)
        print("Models are ready for prediction.\n")

        self.statusLabel.setText("Training of SAE model is finished.")
        self.statusLabel.setStyleSheet('color: rgb(170, 255, 0);')
    

# User interface for file selection
class UI(QMainWindow):
    def __init__(self):
        super(UI, self).__init__()

        # Loading of ui file
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
        
        # Define button's actions
        self.ucitavanje.clicked.connect(self.otvaranje)
        self.labelizacija.clicked.connect(self.preprocessing)
        self.treniraj.clicked.connect(self.odabrane_app)
        self.selektuj.clicked.connect(self.all_app)
        self.deselektuj.clicked.connect(self.none_app)

        # Defining of application's layout
        self.aplikacijeLayout = self.findChild(QVBoxLayout, "aplikacijeLayout")
        self.listA = None

        # Defining of layout for text output during training session
        self.treningText = self.findChild(QTextEdit, "textEdit")
        text=open('Utilities/Guide.txt').read()
        self.treningText.setPlainText(text)

        # Define vasriables
        self.dict_name2label = dict()
        self.counts = dict()
        self.checked_items = [] # lista za cekirane aplikacije      

        # Text from terminal
        sys.stdout = Stream(newText=self.onUpdateText)  
        
        # Showing applications
        self.show()


    # Opening dialog for .pcap file selection 
    def otvaranje(self):
        clean_t()
        # Dialog for file opening
        fname, _ = QFileDialog.getOpenFileName(self, "Open File", "", "PCAP files (*.pcap)")

        # Showing file name and enabling next button
        if fname:
            # Hidding buttons for application control
            self.selektuj.setDisabled(True)
            self.deselektuj.setDisabled(True)
            self.treniraj.setDisabled(True)
            # Writing out path of the file and enabling next button
            self.putanjaLabel.setText(str(fname))
            self.labelizacija.setDisabled(False)


    # File preprocessing
    def preprocessing(self):
        self.treningText.clear()
        clean_t()

        # Buttons that needs to be disabled
        self.labelizacija.setDisabled(True)

        self.filepath = self.putanjaLabel.text()

        self.worker = PreprocessingThread(self.filepath, self.statusLabel, self.dict_name2label)
        self.worker.finished.connect(self.odabir)
        self.worker.finished.connect(self.worker.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()
        

    # Function that creates interface for aplication selection which will be used for training
    def odabir(self):
        self.treningText.clear()
        self.filter_liste()

        self.statusLabel.setStyleSheet('')

        # Enabling buttons for application control
        self.selektuj.setDisabled(False)
        self.deselektuj.setDisabled(False)
        self.treniraj.setDisabled(False)

        self.statusLabel.setText("Discovered applications are shown...")
        sleep(2)

        # QTreeWidget is flexibile way to create list of applications with checkboxes
        if not self.listA:
            self.listA = QTreeWidget()
            self.aplikacijeLayout.addWidget(self.listA)
            self.listA.setColumnCount(3)
            self.listA.setHeaderLabels(['Indeks','Aplikacija','Broj paketa'])
            self.listA.resizeColumnToContents(0)

        # Purging possible previos content of QTreeWidget
        self.listA.clear()

        for key, val in self.counts.items():
            print("{} : {} pakets".format(key, val))
            item = QTreeWidgetItem()
            item.setCheckState(0, Qt.CheckState.Unchecked)
            item.setData(1, Qt.ItemDataRole.UserRole, id(item))
            item.setText(1, key)
            item.setText(2, str(val))
            self.listA.addTopLevelItem(item)

        if len(self.counts) == 0:
            self.statusLabel.setText("Applications in .pcap file don't have enough packets for training. Select different .pcap file.")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')
        else:
            self.statusLabel.setText("Select applications that will be used for classification and then start model training")


    # Selects all shown applications
    def all_app(self):
        def recurse(parent_item):
            for i in range(parent_item.childCount()):
                item = parent_item.child(i)
                item.setCheckState(0, Qt.CheckState.Checked)

        recurse(self.listA.invisibleRootItem())


    # Deselects all chosen applications from selection
    def none_app(self):
        def recurse(parent_item):
            for i in range(parent_item.childCount()):
                item = parent_item.child(i)
                item.setCheckState(0, Qt.CheckState.Unchecked)

        recurse(self.listA.invisibleRootItem())


    # Function that checks which applications are selected, and creates final list of application for training
    def odabrane_app(self):
        # reseting necessary lists and interfaces
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
            # Disabling buttons, buttons are no longer necessary for further process
            self.ucitavanje.setDisabled(True)
            self.selektuj.setDisabled(True)
            self.deselektuj.setDisabled(True)
            self.treniraj.setDisabled(True)

            # Redraw of application list in QTreeWidget-a
            self.listA.clear()
            self.listA.setColumnCount(2)
            self.listA.setHeaderLabels(['Index','Application','Number of packets'])
            for i, app in enumerate(self.checked_items):
                item = QTreeWidgetItem()
                item.setData(0, Qt.ItemDataRole.UserRole, id(item))
                item.setText(0, str(i))
                item.setText(1, app)
                item.setText(2, str(self.counts[app]))
                self.listA.addTopLevelItem(item)
            self.listA.resizeColumnToContents(0)

            # Sledeći korak je treniranje modela
            self.statusLabel.setText("Training model...")
            self.trening()

        elif len(self.checked_items) == 0:
            self.statusLabel.setText("There are no select applications for training")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')

        elif len(self.checked_items) <= 5:
            self.statusLabel.setText("There is not enough applications for training (Minimum is 5)")
            self.statusLabel.setStyleSheet('color: rgb(255, 0, 0);')
            self.none_app()

        print(len(self.checked_items), 'of applications is selected.')
        print('checked_items: ',self.checked_items)


    # Function that calls thread for model training
    def trening(self):

        # Final dict_name2label list
        self.statusLabel.setText("Writing of application list for further use")
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


    # Function that cals thread for applicatiuon list filtering
    def filter_liste(self):
        self.treningText.clear()
        self.worker = LabelingThread(self.filepath, self.statusLabel, self.dict_name2label, self.counts)
        self.worker.finished.connect(self.worker.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.start()


    # Resets elements of graphic interface to starting values
    def reset_ui(self):
        # Purging content
        self.listA.clear()

        # Enabling buttons
        self.ucitavanje.setDisabled(False)
        # Disabling buttons
        self.selektuj.setDisabled(True)
        self.deselektuj.setDisabled(True)
        self.treniraj.setDisabled(True)

    
    # For text input procedure to QTextEdit
    def onUpdateText(self, text):
        """Write console output to text widget."""
        cursor = self.treningText.textCursor()
        #cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.treningText.setTextCursor(cursor)
        self.treningText.ensureCursorVisible()


    # Destructor method for sys.stdout
    def __del__(self):
        sys.stdout = sys.__stdout__


# Initialisation of application
app = QApplication(sys.argv)
UIWindow = UI()


# Opening qss file
styleFile = open("./Utilities/Integrid.qss",'r')
with styleFile:
    qss = styleFile.read()
    app.setStyleSheet(qss)


# Application execution
app.exec()