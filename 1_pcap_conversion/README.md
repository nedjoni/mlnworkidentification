# Scripts for pcap conversion

## Conversion from pcapng to pcap files
python pcapng2pcap.py

## Preparation of nDPI bases
python ndpi_base.py

## Getting applications list
python apps_list.py

## Defining applications
utils.py

## Converting from pcap files to labeled pcap files
python pcapng2pcap.py

## Preprocessing labeled pcap files to pickle files
python prepro.py


# Splitting big pcap files (Sometime is necessary for memory management)

## Windows:
"C:\Program Files\Wireshark\editcap.exe" -c 10000 example1.pcap example2.pcap

## Ubuntu
editcap -c 10000 example1.pcap example2.pcap


