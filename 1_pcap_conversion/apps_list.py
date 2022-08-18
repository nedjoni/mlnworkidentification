import os
from os import path
import pandas as pd
import csv
  
nf_dir = r'./DPI'
file_counter = 'counter.csv'

# lists with aplications and their count, empty if new counter.csv created
apps, count_app = [], []
  
# Loading file counter.csv, if it doesn't exists - create it if
if (path.exists(file_counter) and os.stat(file_counter).st_size>0):
    df = pd.read_csv(file_counter, header=0, sep=';')
    data_index = df.columns.tolist()
    data_array = df.values

    for data in data_array:
        apps.append(data[data_index.index('application')])
        count_app.append(data[data_index.index('count')])

# reading csv file, the only important column is one with applications
def read_csv_file(file_path):
    try:
        df = pd.read_csv(file_path, header=0, sep=',')
        data_index = df.columns.tolist()
        data_array = df.values

        for data in data_array:
            app_name = str(data[data_index.index("application_name")])
            if app_name in apps:
                count_indx = apps.index(app_name)
                count_app[count_indx] = count_app[count_indx] +1
            else:
                apps.append(app_name)
                count_app.append(1)

    except NameError:
        print("Empty PCAP file or something else")

# Read nDPI files
try:
    # iterate through all file
    for file in os.scandir(nf_dir):
        # Check whether file is in csv format or not
        if file.name.endswith(".csv") and (os.stat(file).st_size>0):
            file_path = f"{nf_dir}/{file.name}"
            print(file_path)
            # call read csv file function
            read_csv_file(file_path)
except NameError:
    print("Something is wrong with files or code")

# Saving aplications and their count to counter.csv file
# newline parameter required for Windows line translation
with open(file_counter, 'w', newline='') as f:
    writer = csv.writer(f, delimiter=';')
    header = ['No', 'application', 'count']
    writer.writerow(header)
    for idx, app in enumerate(apps):
        data = (idx+1, app, count_app[idx])
        writer.writerow(data)
    f.close()

print("Creation of counter.csv is finished")