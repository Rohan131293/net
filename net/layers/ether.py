from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
import struct

class Ether(Layer):
	ether_types = {2048:'IPv4',2054:'ARP',32821:'RARP',33024:'VLAN Tagged Frame (IEEE 802.1Q)',
		33100:'SNMP',34525:'IPv6',34887:'MPLS Unicast',34888:'MPLS Multicast',34928:'Jumbo Frames',
		34958:'EAP over LAN(IEEE 802.1X)',34969:'Ethernet II',35045:'MAC Security (IEEE 802.1AE)',
		35063:'Precision Time Protocol(IEEE 1588)'}

	default_length = 14
	@staticmethod
	def help():
		print('#Ethernet Frame Header')
		Structure=[{'Destination MAC(6 Bytes)':16},{'Source MAC(6 Bytes)':16},
			{'Type(2 Bytes)':16}, {'Payload(1500 Bytes)':16}]

		Formatter.printStruct(Structure)
		
		print('\nethLayer = Ether(dst="00:00:00:00:00:00",src="00:00:00:00:00:00")')

		print('#Parameters:')
		print ('Ether().src = "00:00:00:00:00:00"')
		print ('Ether().dst = "00:00:00:00:00:00"')
		print ('Ether().ether_type = 2048 ')
		
		print ('\n#Supported Types:')
		sorted_keys = sorted(Ether.ether_types.keys())
		for key in sorted_keys: 
			print (str(key)+': '+str(Ether.ether_types[key]))

		print('\n#Methods:\n1)encoded = Ether().encode(): Returns encoded ethernet frameHeader')
		print('2)remData = Ether().decode(raw): Decodes parameter from given raw data')
		print('3)Ether().show(): Displays parameters')
		print('4)Ether.help(): Displays this message')

	def __init__(self,dst="00:00:00:00:00:00",src="00:00:00:00:00:00"):
		self.dst=dst
		self.src=src
		self.ether_type=2048

	def show(self):
		print('#Ethernet Header:\ndst={}\nsrc={}\nether_type={}\n'
			.format(self.dst.upper(),self.src.upper(),self.ether_type))
	
	def summary(self):
		ether_type=""
		if(self.ether_type in Ether.ether_types.keys()):
			ether_type = Ether.ether_types[self.ether_type]
		else:
			ether_type = str(self.ether_type)
		print('#Ethernet Header: Source MAC-> {}, Destination MAC-> {}, Frame Type-> {}'
			.format(self.src.upper(),self.dst.upper(),ether_type))

	def encode(self):
		encoded=None
		if(self.ether_type in Ether.ether_types.keys()):
			encoded=struct.pack('! 6s 6s H',Formatter.mac_to_bytes(self.dst),
				Formatter.mac_to_bytes(self.src),int(self.ether_type))
		else:
			print('Undefined Type {} for Ether().ether_type'.format(self.ether_type))
			Ether.help()
		return encoded

	def decode(self,raw):
		ether_dst,ether_src,self.ether_type=struct.unpack('! 6s 6s H',raw[:Ether.default_length])
		self.dst=Formatter.bytes_to_mac(ether_dst)
		self.src=Formatter.bytes_to_mac(ether_src)
		return raw[Ether.default_length:]