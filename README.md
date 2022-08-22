# Machine Learning Network Traffic Identification
This set of scripts was made to test capabilities of network traffic identification with Deep Learning methods, testing various machine learning methods.
This work is based on ideas of various researches, mostly on [Deep Packet: A Novel Approach For Encrypted Traffic Classification Using Deep Learning](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwiolILc3dn5AhWmiv0HHcG8AvsQFnoECAkQAQ&url=https%3A%2F%2Farxiv.org%2Fabs%2F1709.02656&usg=AOvVaw3owgSbASsCWuOK25zcpmFm) and [deeplearning-network-traffic](https://github.com/akshitvjain/deeplearning-network-traffic).

## Installation

Use the package manager [pip](https://pip.pypa.io/en/stable/) to install foobar.
Scripts are tested under Windows, by using [Anaconda](https://www.anaconda.com/), and also tested as working under Linux.
All necessary modules and libraries are listed in file requirements.txt, and can be installed using command:
```bash
pip install -r requirements.txt
```

## Collecting traffic

There is one script included with all the necessary folders. It collects traffic from the internet interface. In my case I collected it using SPAN option on local switch.
To start it you only need to run command:
```bash
python pcapcollector.py
```

## Traffic conversion

This is bundle of scripts I used to convert pcap files to data set, which will be used for machine learning.

Sometime necessary conversion from pcapng to pcap files can be done using:
```bash
python pcapng2pcap.py
```

[NFStream](https://www.nfstream.org/) uses [nDPI](https://www.ntop.org/products/deep-packet-inspection/ndpi/) module for DPI extraction of Metadata. 
Preparation of nDPI bases can be done using:
```bash
python ndpi_base.py
```

Optional, but convinient way to extract application names from nDPI base:
```bash
python apps_list.py
```

List of application needs to be stored for further use and file **utils.py** is used for that.

Preprocessing labeled pcap files to pickle files makes preprocessed data to be loaded later. This scripts is borrowed from similar work on [deeppacket](https://github.com/KimythAnly/deeppacket)
```bash
python prepro.py
```

Splitting big pcap files (Sometime is necessary for memory management):

Windows
```bash
"C:\Program Files\Wireshark\editcap.exe" -c 10000 example1.pcap example2.pcap
```
Ubuntu
```bash
editcap -c 10000 example1.pcap example2.pcap
```

## Tuning

This is optional, but can give some insight in what parameters works best with different Machine Learning methods.
It is also time and resource consuming, and the best way is to optimise it for online platforms like [Colab](https://colab.research.google.com/) or [Kaggle](https://www.kaggle.com/).

## Training and testing

Here are presented three Machine Learning metods: Convolutional Neural Network, Stacked Autoencoder and Multilayer Perceptron. Parameters are chosen from the results of tuning
This is also time and resource consuming, so use of ML platforms is recommended.

## Application for training and prediction

This is additional project made for interactive, graphic ML train of traffic data, and prediction on trained models.
Training can be done by using 
```bash
python train.py
```
and prediction using
```bash
python predict.py
```
It is necessary to have [Wireshark](https://www.wireshark.org/) or [Npcap](https://npcap.com/) installed.

