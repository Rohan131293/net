from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
import struct

class ARP(Layer):
	op_values = {1:'Request', 2:'Response'}

	default_length = 28
	@staticmethod
	def help():
		print('#ARP Packet Header')
		Structure=[{'Hardware Type(2 Bytes)':16},{'Protocol Type(2 Bytes)':16},
			{'Header Length':8}, {'Protocol Length':8}, {'Operation(2 Bytes)':16},
			{'Sender Hardware Address(6 Bytes)':16},{'Sender Protocol Address(4 Bytes)':16},
			{'Target Hardware Address(6 Bytes)':16},{'Target Protocol Address(4 Bytes)':16}]

		Formatter.printStruct(Structure)
		
		print('\narpLayer = ARP(op = 1, hwsrc = "00:00:00:00:00:00", psrc = "127.0.0.1", hwdst = "00:00:00:00:00:00", pdst = "127.0.0.1")')

		print('#Parameters:')
		print('ARP().hwtype = 0x0001')#http://www.embeddedsystemtesting.com/2012/08/what-is-hardware-type-in-arp-header.html
		print('ARP().ptype = 0x0800')
		print('ARP().hwlen = 0x06')
		print('ARP().plen = 0x04')
		print('ARP().op = 1') 
		print('ARP().hwsrc = "00:00:00:00:00:00"')
		print('ARP().psrc = "127.0.0.1"')
		print('ARP().hwdst = "00:00:00:00:00:00"')
		print('ARP().pdst = "127.0.0.1"')
		
		print ('\n#Supported op Types:')
		for key in ARP.op_values: 
			print (str(key)+': '+str(ARP.op_values[key]))

		print('\n#Methods:\n1)encoded = ARP().encode(): Returns encoded ARP Header')
		print('2)remData = ARP().decode(raw): Decodes parameter from given raw data')
		print('3)ARP().show(): Displays parameters')
		print('4)ARP.help(): Displays this message')

	def __init__(self,op = 1,hwsrc = "00:00:00:00:00:00",psrc = "127.0.0.1",hwdst = "00:00:00:00:00:00",pdst = "127.0.0.1"):
		self.hwtype = 0x0001#Ethernet
		self.ptype = 0x0800
		self.hwlen = 0x06
		self.plen = 0x04
		self.op = op
		self.hwsrc = hwsrc
		self.psrc = psrc
		self.hwdst = hwdst
		self.pdst = pdst

	def show(self):
		print('#ARP Header:\nhwtype = {}\nptype = {}\nhwlen = {}\nplen = {}\nop = {}\nhwsrc = {}\npsrc = {}\nhwdst = {}\npdst = {}\n'
			.format(self.hwtype,self.ptype,self.hwlen,self.plen,self.op,self.hwsrc.upper(),self.psrc,self.hwdst.upper(),self.pdst))
	
	def summary(self):
		if(self.op==1):#ARP Request
			print("#ARP Request: who has {} tell {}".format(self.pdst,self.psrc))
		elif(self.op==2):#ARP Reply
			print("#ARP Reply: {} is at {}".format(self.hwsrc,self.psrc))
		else:
			logging.error('Undefined op value {} for ARP().op'.format(self.op))
			ARP.help()

	def encode(self):
		encoded=None
		if(self.op not in ARP.op_values.keys()):
			logging.error('Undefined op value {} for ARP().op'.format(self.op))
			ARP.help()
			return encoded

		encoded=struct.pack('! H H B B H 6s 4s 6s 4s',
			self.hwtype,self.ptype,self.hwlen,self.plen,self.op,Formatter.mac_to_bytes(self.hwsrc),
			Formatter.ip_to_bytes(self.psrc),Formatter.mac_to_bytes(self.hwdst),
			Formatter.ip_to_bytes(self.pdst))
		
		return encoded

	def decode(self,raw):
		self.hwtype,self.ptype,self.hwlen,self.plen,self.op,hwsrc,psrc,hwdst,pdst = struct.unpack('! H H B B H 6s 4s 6s 4s',
			raw[:ARP.default_length:])
		self.hwsrc=Formatter.bytes_to_mac(hwsrc)
		self.psrc=Formatter.bytes_to_ip(psrc)
		self.hwdst=Formatter.bytes_to_mac(hwdst)
		self.pdst=Formatter.bytes_to_ip(pdst)
		return raw[ARP.default_length:]