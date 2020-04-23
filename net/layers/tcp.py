from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
import struct

class TCP(Layer):
	default_length = 20

	@staticmethod
	def help():
		print('#TCP Packet Header')
		Structure=[{'Source Port(2 Bytes)':16},{'Destination Port(2 Bytes)':16},
		{'Sequence Number(4 Bytes)':16},{'Acknowledgment Number(4 Bytes)':16},
		{'Offset':4},{'Reserved':3},{'TCP flags':1},{'TCP flags cont.':8},
		{'Window(2 Bytes)':16},{'Checksum(2 Bytes)':16},{'Urgern Pointer(2 Bytes)':16},
		{'TCP Options (Not Supported)':16}]

		Formatter.printStruct(Structure)
		print('\ntcpLayer = TCP(sport = 0, dport = 0, seq = 0, ack = 0)')
		
		print('#Parameters:')
		print('TCP().sport = 0')
		print('TCP().dport = 0')
		print('TCP().seq = 0')
		print('TCP().ack = 0')
		print('TCP().dataofs = 5 (4 Bits ) Min:5,Max:15 (Actual = dataofs * 4)')
		print('TCP().reserved = 0 (3 Bits Usually 0)')
		print('TCP().flags = {} (9 Bits)')
		print('TCP().window = 0')
		print('TCP().chksum = 0')
		print('TCP().urgptr = 0')
		print('TCP().options = {} Not Supported yet')

		print('\n* Explicit Congestion Notification')
		print('TCP().flags["ecn_nounce"]= 0 Nonce Sum')
		print('TCP().flags["ecn_cwr"]= 0 CWR')
		print('TCP().flags["ecn_ece"]= 0 ECE')

		print('\n* Control Bits:')
		print('TCP().flags["cb_urg"]= 0 Urgent Pointer')		
		print('TCP().flags["cb_ack"]= 0 Acknowledgement')
		print('TCP().flags["cb_push"]= 0 Push Flag')
		print('TCP().flags["cb_reset"]= 0 Reset Connection')
		print('TCP().flags["cb_sync"]= 1 Synchronize')
		print('TCP().flags["cb_fin"]= 0 FIN')


		print('\n#Methods:\n1)encoded = TCP().encode(): Returns encoded TCP Header')
		print('2)remData = TCP().decode(raw): Decodes parameter from given raw data')
		print('3)TCP().show(): Displays parameters')
		print('4)TCP.help(): Displays this message')

	def __init__(self, sport = 0, dport = 0, seq = 0, ack = 0):
		self.sport=sport
		self.dport = dport
		self.seq = seq
		self.ack = ack
		self.dataofs = 5 
		self.reserved = 0#Mainly 0
		self.flags = {}
		self.window = 0
		self.chksum = 0
		self.urgptr = 0

		#To Do: Handle and provide support for options field
		
		#Explicit Congestion Notification
		self.flags['ecn_nounce'] = 0 #Nonce Sum
		self.flags['ecn_cwr']    = 0 #CWR
		self.flags['ecn_ece']    = 0 #ECE

		#Control Bits
		self.flags['cb_urg']   = 0 #Urgent Pointer		
		self.flags['cb_ack']   = 0 #Acknowledgement
		self.flags['cb_push']  = 0 #Push Flag
		self.flags['cb_reset'] = 0 #Reset Connection
		self.flags['cb_sync']  = 1 #Synchronize
		self.flags['cb_fin']   = 0 #FIN

	def show(self):
		print('#TCP Header:\nsport = {}\ndport = {}\nseq = {}\nack = {}\ndataofs = {}\nreserved = {}\nflags = {}\nwindow = {}\nchksum = {}\nurgptr = {}\n'
			.format(self.sport,self.dport,self.seq,self.ack,self.dataofs,self.reserved,self.flags,self.window,self.chksum,self.urgptr))
	
	def summary(self):
		print("#TCP Header: Source Port-> {}, Destination Port-> {}, Sequence No.-> {}, ACK No.-> {} "
			.format(self.sport,self.dport,self.seq,self.ack))
			
	def encode(self):
		flags_val = 0 
		#Explicit Congestion Notification
		flags_val = flags_val + (self.flags['ecn_nounce'] << 8)  #Nonce Sum
		flags_val = flags_val + (self.flags['ecn_cwr'] << 7) #CWR
		flags_val = flags_val + (self.flags['ecn_ece'] << 6)  #ECE

		#Control Bits
		flags_val = flags_val + (self.flags['cb_urg'] << 5)  #Urgent Pointer		
		flags_val = flags_val + (self.flags['cb_ack'] << 4)  #Acknowledgement
		flags_val = flags_val + (self.flags['cb_push'] << 3) #Push Flag
		flags_val = flags_val + (self.flags['cb_reset'] << 2) #Reset Connection
		flags_val = flags_val + (self.flags['cb_sync']  << 1) #Synchronize
		flags_val = flags_val + (self.flags['cb_fin']) #FIN
		
		tcp_orf = (self.dataofs << 12) + (self.reserved << 9) + flags_val
		encoded=struct.pack('! H H L L H H H H',self.sport,self.dport,self.seq,self.ack,tcp_orf,self.window,self.chksum,self.urgptr)#(2+2+4+4+2+2+2+2)			
		return encoded

	def decode(self,raw):
		self.sport,self.dport,self.seq,self.ack,tcp_orf,self.window,self.chksum,self.urgptr=struct.unpack('! H H L L H H H H',raw[:TCP.default_length])#(2+2+4+4+2+2+2+2)
		self.dataofs = (tcp_orf >> 12 )
		#Reserved Flags
		self.reserved = (tcp_orf & int('0b0000111000000000',2)) >> 9 #Extracting Reserved Flags
		#Explicit Congestion Notification
		self.flags['ecn_nounce'] = (tcp_orf & 256) >> 8 #Nonce Sum
		self.flags['ecn_cwr'] = (tcp_orf & 128) >> 7 #CWR
		self.flags['ecn_ece'] = (tcp_orf & 64) >> 6 #ECE

		#Control Bits
		self.flags['cb_urg'] = (tcp_orf & 32) >> 5 #Urgent Pointer		
		self.flags['cb_ack'] = (tcp_orf & 16) >> 4 #Acknowledgement
		self.flags['cb_push'] = (tcp_orf & 8) >> 3 #Push Flag
		self.flags['cb_reset'] = (tcp_orf & 4) >> 2 #Reset Connection
		self.flags['cb_sync'] = (tcp_orf & 2) >> 1 #Synchronize
		self.flags['cb_fin'] = (tcp_orf & 1) #FIN
		
		return raw[(self.dataofs*4):]