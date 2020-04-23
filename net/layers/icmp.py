from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
from random import randint
import struct

class ICMP(Layer):
	icmp_types={0:'Echo Reply',3:'Destination Unreachable',4:'Source Quench',5:'Redirect',8:'Echo Request',
		9:'Router Advertisement',10:'Router Selection',11:'Time Exceeded',12:'Parameter Problem',13:'Timestamp',
		14:'Timestamp Reply',15:'Information Request',16:'Information reply',17:'Address Mask Request',
		18:'Address Mask Reply',30:'Traceroute'}

	default_length = 8

	@staticmethod
	def help():
		print('#ICMP Packet Header')
		Structure=[{'ICMP Type':8},{'ICMP Code':8},{'ICMP Header Checksum(2 Bytes)':16},
		{'Identifiers(2 Bytes)':16},{'Sequence Number(2 Bytes)':16},
		{'Data(Variable Length)':16}]

		Formatter.printStruct(Structure)
		print('Note : Data field not yet supported.')
		print('\nicmpLayer = ICMP(ptype = 8,seq = 1)')
		
		print('#Parameters:')
		print('ICMP().ptype = 8')
		print('ICMP().code = 0')
		print('ICMP().chksum = 0')
		print('ICMP().id = 4385')
		print('ICMP().seq = 1')

		print ('\n#Supported ICMP Types:')
		sorted_keys = sorted(ICMP.icmp_types.keys())
		for key in sorted_keys:
			print (str(key)+' : '+str(ICMP.icmp_types[key]))

		print('\n#Methods:\n1)encoded = ICMP().encode(): Returns encoded ICMP Header')
		print('2)remData = ICMP().decode(raw): Decodes parameter from given raw data')
		print('3)ICMP().show(): Displays parameters')
		print('4)ICMP.help(): Displays this message')

	def __init__(self,ptype=8,seq=1):
		self.ptype=ptype
		self.code=0
		self.chksum=0
		self.id=randint(0,0xFFFF)#0xe88d,0x69c7
		self.seq=seq
		#To Do: Add Support for Data Field

	def show(self):
		print('#ICMP Layer:\nptype = {}\ncode = {}\nchksum = {}\nid = {}\nseq = {}\n'
			.format(self.ptype,self.code,self.chksum,self.id,self.seq))
	
	def summary(self):
		if(self.ptype not in ICMP.icmp_types.keys()):
			logging.error('Undefined Type {} for ICMP().ptype'.format(self.ptype))
			ICMP.help()
			return
		ptype = ICMP.icmp_types[self.ptype]
		print("#ICMP Layer : ICMP TYPE-> {}, ICMP ID-> {}, ICMP SEQ-> {}"
			.format(ptype,self.id,self.seq))
			
	def encode(self):
		encoded = None
		if(self.ptype not in ICMP.icmp_types.keys()):
			logging.error('Undefined Type {} for ICMP().ptype'.format(self.ptype))
			ICMP.help()
			return encoded

		encoded = struct.pack('! B B H H H',self.ptype,self.code,self.chksum,self.id,self.seq)#(1+1+2+2+2)			
		return encoded


	def decode(self,raw):
		self.ptype,self.code,self.chksum,self.id,self.seq=struct.unpack('! B B H H H',raw[:ICMP.default_length])
		return raw[ICMP.default_length:]