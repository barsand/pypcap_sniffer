# net::packet
# dpkt			easy pcapy  

import socket
from struct import *
import datetime
import pcapy
import sys

import time
import argparse

FILE_COUNTER = 0
FILE_COUNTER_LIMIT = None
FILE_PTR = None

def str2file (out_pfx, string):

	# print "FILE_COUNTER_LIMIT", FILE_COUNTER_LIMIT


	curr_t = time.time()
	timestamp = datetime.datetime.fromtimestamp(curr_t).strftime('%Y%m%d_%H%M%S')
	global FILE_COUNTER
	global FILE_COUNTER_LIMIT
	global FILE_PTR

	if FILE_COUNTER >= FILE_COUNTER_LIMIT:
		FILE_PTR.close()
		FILE_COUNTER = 0

	if FILE_COUNTER == 0:
		file_path = timestamp + "-" + out_pfx + ".txt"
		FILE_PTR = open(file_path, 'w')
		
	FILE_COUNTER+=1;
	FILE_PTR.write(timestamp + " " + string + '\n')

def opts_parser():
	
	parser = argparse.ArgumentParser(description='''logs all traffic in specified network device''')
	
	# required arguments
	args_group = parser.add_argument_group('required arguments')
	args_group.add_argument('-o', metavar='outfile', help='output files pfx', required=True)
	args_group.add_argument('-l', metavar='limit', help='packet count limit per log file', required=True)

	
	return parser.parse_args()
 
def main(argv):
	#list all devices

	args = opts_parser()
	out_pfx = args.o
	global FILE_COUNTER_LIMIT
	FILE_COUNTER_LIMIT = args.l

	devices = pcapy.findalldevs()
	print devices
	 
	#ask user to enter device name to sniff
	print "Available devices are :"
	for d in devices :
		print d
	
	dev = raw_input("Enter device name to sniff : ")
	 
	print "Sniffing device " + dev
	 
	'''
	open device
	# Arguments here are:
	#   device
	#   snaplen (maximum number of bytes to capture _per_packet_)
	#   promiscious mode (1 for true)
	#   timeout (in milliseconds)
	'''
	cap = pcapy.open_live(dev , 65536 , 1 , 0)
 
	#start sniffing packets
	while(1) :
		(header, packet) = cap.next()
		#print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
		parse_packet(packet, out_pfx)
 
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
	return b
 
#function to parse a packet
def parse_packet(packet, out_pfx) :
	 
	#parse ethernet header
	eth_length = 14
	 
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])
	str2file(out_pfx, 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))
 
	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		 
		#now unpack them :)
		iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF
 
		iph_length = ihl * 4
 
		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
 
		str2file(out_pfx, 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))
 
		#TCP protocol
		if protocol == 6 :
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]
 
			#now unpack them :)
			tcph = unpack('!HHLLBBHHH' , tcp_header)
			 
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4
			 
			str2file(out_pfx, 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
			 
			h_size = eth_length + iph_length + tcph_length * 4
			data_size = len(packet) - h_size
			 
			#get data from the packet
			data = packet[h_size:]
			 
			str2file(out_pfx, 'Data : ' + data)
 
		#ICMP Packets
		elif protocol == 1 :
			u = iph_length + eth_length
			icmph_length = 4
			icmp_header = packet[u:u+4]
 
			#now unpack them :)
			icmph = unpack('!BBH' , icmp_header)
			 
			icmp_type = icmph[0]
			code = icmph[1]
			checksum = icmph[2]
			 
			str2file(out_pfx, 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
			 
			h_size = eth_length + iph_length + icmph_length
			data_size = len(packet) - h_size
			 
			#get data from the packet
			data = packet[h_size:]
			 
			str2file(out_pfx, 'Data : ' + data)
 
		#UDP packets
		elif protocol == 17 :
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]
 
			#now unpack them :)
			udph = unpack('!HHHH' , udp_header)
			 
			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			 
			str2file(out_pfx, 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
			 
			h_size = eth_length + iph_length + udph_length
			data_size = len(packet) - h_size
			 
			#get data from the packet
			data = packet[h_size:]
			 
			str2file(out_pfx, 'Data : ' + data)
 
		#some other IP packet like IGMP
		else :
			str2file(out_pfx, 'Protocol other than TCP/UDP/ICMP')
			 
		# print
 
if __name__ == "__main__":
  main(sys.argv)
