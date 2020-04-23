from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
import struct

class UDP(Layer):
	default_length = 8

	@staticmethod
	def help():
		print('#UDP Packet Header')
		Structure=[{'Source Port(2 Bytes)':16},{'Destination Port(2 Bytes)':16},
		{'Length(2 Bytes)':16},{'Checksum(2 Bytes)':16}]

		Formatter.printStruct(Structure)
		print('\nudpLayer = UDP(sport = 0, dport = 0, plen = 0)')
		
		print('#Parameters:')
		print('UDP().sport = 0')
		print('UDP().dport = 0')
		print('UDP().plen = 0')
		print('UDP().chksum = 0')

		print('\n#Methods:\n1)encoded = UDP().encode(): Returns encoded UDP Header')
		print('2)remData = UDP().decode(raw): Decodes parameter from given raw data')
		print('3)UDP().show(): Displays parameters')
		print('4)UDP.help(): Displays this message')

	def __init__(self,sport=0,dport=0,plen=0):
		self.sport = sport
		self.dport = dport
		self.plen = plen
		self.chksum = 0

	def show(self):
		print('#UDP Header:\nsport = {}\ndport = {}\nplen = {}\nchksum = {}\n'
			.format(self.sport,self.dport,self.plen,self.chksum))
	
	def summary(self):
		print("#UDP Header: Source Port-> {}, Destination Port-> {}"
			.format(self.sport,self.dport))
			
	def encode(self):
		encoded = struct.pack('! H H H H',self.sport,self.dport,self.plen,self.chksum)#(2+2+2+2)			
		return encoded

	def decode(self,raw):
		self.sport,self.dport,self.plen,self.chksum = struct.unpack('! H H H H',raw[:UDP.default_length])
		return raw[UDP.default_length:]