#Packet sniffer in Python
#Linux based implementation

'''
import socket

#create an INET raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

#receive a packet
while True:
	print s.recvfrom(65565)

'''
import socket, sys
from struct import *

#Get string of 6 characters as ethernet address into dash seperated hex string
def eth_addr(a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0],a[1],a[2],a[3],a[4],a[5])
	return b

#create an INET, STREAMing socket
try:
	#s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
	#AF_INET is the family of sockets created - TCP or UDP
	#Socket type is SOCK_RAW instead of SOCK_STREAM or SOCK_DGRAM
	#Socket protocol specified is IP-PROTO_<TCP/UDP/ICMP>
except socket.error as error:
	print('Socket could not be created. Error: %s. Message: %s.' %(error.errno, error.strerror)) 
	sys.exit(1)
count = 0
print('Getting a packet\n\n')
#get a packet 
while True:
	packet = s.recvfrom(65565)
	#keep in mind that this port binding won't work in Windows
	#Windows uses a Winsock API hook or Winpcap driver for sockets
	#socket.recvfrom(buffersize,[flags]) gets the data from the socket. O/P - (string,address)

	print ('Packet Received: %s\n\n' % packet)
	count = count+1
	#packet string from tuple
	packet = packet[0]
	
	#-------------------L2 Information-------------------------------------
	eth_length = 14
	eth_header = packet[:eth_length]
	eth_unpack =  unpack('!6s6sH', eth_header)
	eth_protocol = socket.ntohs(eth_unpack[2])
	print('###############Layer 2 Information############')
	print('Destination MAC: %s' % eth_addr(packet[0:6]))
	print('Source MAC: %s' % eth_addr(packet[6:12]))
	print('Protcol: %s' % eth_protocol)
	print('-----------------------------------------------------------------\n\n' )
	
        #-------------------IP HEADER EXTRACTION--------------------------------
	#take the first 20 characters for the IP header
	ip_header = packet[0:20]
	
	#now unpack 'em
	header_unpacked = unpack('!BBHHHBBH4s4s', ip_header)
	#https://docs.python.org/2/library/struct.html#format-characters
	
	version_ih1= header_unpacked[0] 
	version = version_ih1 >> 4 
	ih1 = version_ih1 & 0xF
	
	iph_length = ih1*4
	
	ttl = header_unpacked[5]
	protocol = header_unpacked[6]
	source_add = socket.inet_ntoa(header_unpacked[8])
	destination_add = socket.inet_ntoa(header_unpacked[9])
	print('##########IP Header Info##############')
	print('Version : %s\nIP Header Length: %s\nTTL: %s\nProtocol: %s\nSource Address: %s\nDestination Address: %s' % (version, ih1, ttl, protocol, source_add, destination_add))
	print('-------------------------------------------\n\n')

	#-----------------------------------------------------------------------------

	#----------------TCP HEADER EXTRACTION----------------------------------------
	#tcp_header = packet[iph_length:iph_length+20] 
	#t=iph_length+eth_length
	tcp_header = packet[iph_length:iph_length+20]

	#unpack them 
	tcph = unpack('!HHLLBBHHH', tcp_header)
	
	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	ack = tcph[3]
	resrve = tcph[4]
	tcph_len = resrve >> 4

	#print it all out
	print('###########TCP Header Info##############')
	print('Source Port: %s' % source_port)
	print('Destination Port: %s' % dest_port)
	print('Sequence Number: %s' % sequence)
	print('Acknowledgement: %s' % ack)
	print('TCP Header Length: %s' % tcph_len)
	print('------------------------------------------\n\n')
	#-------------------------------------------------------------------------------

	#------------------------Get the DATA-------------------------------------------
	h_size = iph_length+tcph_len*4
	data_size = len(packet)-h_size

	#get the data yo!
	data = packet[h_size:]
	
	print('##############DATA##################')
	print('Data: %s' % data)
	print('------------------------------------\n\n')

	print('Packet %d is done!\n' % count)

