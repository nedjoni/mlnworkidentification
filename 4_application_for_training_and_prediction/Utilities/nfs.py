import sys
from nfstream import NFStreamer

filepath = str(sys.argv[1])
nf_path = str(sys.argv[2])



if __name__ == '__main__':
	df = NFStreamer(source= filepath).to_pandas()[["src_ip", "src_port", "dst_ip", "dst_port", "application_name"]]
	df.to_csv(nf_path)