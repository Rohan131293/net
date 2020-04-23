from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
import struct

class IPv4(Layer):
	#https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	MAX_IP_LEN = 65535
	MIN_IP_LEN = 576
	ip_protocols={1:'ICMP',2:'IGMP',6:'TCP',9:'IGRP',17:'UDP',41:'IPv6 encapsultation',
		47:'GRE',50:'ESP',89:'Open Shortest Path First',132:'SCTP'}

	@staticmethod
	def help():
		print('#IP Packet Header')
		Structure=[{'version':4},{'Hdr Length':4},{'Service Type':8},{'Length(2 Bytes)':16},
		{'Identification(2 Bytes)':16},{'Flags':3},{'Frag Offset':5},{'Frag Offset cont.':8},
		{'Time To Live':8},{'Protocol':8},{'Checksum(2 Bytes)':16},{'Source IP Address(4 Bytes)':16},
		{'Destination IP Address(4 Bytes)':16}]

		Formatter.printStruct(Structure)
		
		print('\nipv4Layer = IPv4(proto = 6, src = "127.0.0.1", dst = "127.0.0.1",ip_len = 576)')
		
		print('#Parameters:')
		print('IPv4().version = 4 for IPv4 ')
		print('IPv4().ihl = 5 Min:5 Max:15 , Header Length= ihl * 4 bytes i.e. 1 ihl = 32 bits')
		print('IPv4().tos = 0 ,QOS related')
		print('IPv4().ip_len = IPv4.MIN_IP_LEN Min:576,Max:65535 (Header+Data)')
		print('IPv4().id = 1 To Identify Fragment Origin')
		print('IPv4().flags = 2 1:Reserved,2:Do not Fragment,4:More Fragment')
		print('IPv4().frag = 0 (13 bit)')
		print('IPv4().ttl = 64')
		print('IPv4().proto = 6 for TCP')
		print('IPv4().chksum = 0 Header Checksum')
		print('IPv4().src = "127.0.0.1"')
		print('IPv4().dst = "127.0.0.1"')

		print ('\n#Supported Protocol Types:')
		sorted_keys = sorted(IPv4.ip_protocols.keys())
		for key in sorted_keys:
			print (str(key)+' : '+str(IPv4.ip_protocols[key]))

		print('\n#Methods:\n1)encoded = IPv4().encode(): Returns encoded IPv4 Header')
		print('2)remData = IPv4().decode(raw): Decodes parameter from given raw data')
		print('3)IPv4().show(): Displays parameters')
		print('4)IPv4.help(): Displays this message')

	def __init__(self,proto = 6,src = "127.0.0.1",dst = "127.0.0.1",ip_len = 576):
		self.version = 4 #4:IPv4,6:Ipv6
		self.ihl = 5 #Header Length :Considering No Addtional Options
		self.tos = 0x00 #Type of Service:QOS Features , Not Used 
		self.ip_len = ip_len #Total Length:(Header+Data)Min 576,Max:65535
		self.id = 1 #To Identify Fragment Origin
		self.flags = 2 #Fragmentation Flags
		self.frag = 0 #Considering No Fragmentation, Fragmentation Offset is Ignored
		self.ttl = 64 # Time to live
		self.proto = proto 
		self.chksum = 0 #Header Checksum: Validity checked at every stage
		self.src = src
		self.dst = dst

	def show(self):
		print('#IP Header:\nversion = {}\nihl = {}\ntos = {}\nip_len = {}\nid = {}\nflags = {}\nfrag = {}\nttl = {}\nproto = {}\nchksum = {}\nsrc = {}\ndst = {}\n'
			.format(self.version,self.ihl,self.tos,self.ip_len,self.id,self.flags,self.frag,
				self.ttl,self.proto,self.chksum,self.src,self.dst))
	
	def summary(self):
		if(self.proto not in IPv4.ip_protocols.keys()):
			logging.error('Undefined protocol {} for IPv4().proto'.format(self.proto))
			IPv4.help()
			return	
		protocol = IPv4.ip_protocols[self.proto]
		print("#IPv4 Header : Source IP-> {}, Destination IP-> {}, Protocol-> {}"
			.format(self.src,self.dst,protocol))
			
	def encode(self):
		encoded = None
		if(self.proto not in IPv4.ip_protocols.keys()):
			logging.error('Undefined protocol {} for IPv4().proto'.format(self.proto))
			IPv4.help()
			return encoded

		ip_version_hlen = (self.version << 4) + self.ihl
		ip_flag_frag = (self.flags << 13) + self.frag
		encoded = struct.pack('! B B H H H B B H 4s 4s',ip_version_hlen,self.tos,self.ip_len,self.id,
			ip_flag_frag,self.ttl,self.proto,self.chksum,Formatter.ip_to_bytes(self.src),
			Formatter.ip_to_bytes(self.dst))			
		return encoded


	def decode(self,raw):
		version_hlen,self.tos,self.ip_len,self.id,flag_frag,self.ttl,self.proto,self.chksum,src,dst = struct.unpack('!B B H H H B B H 4s 4s',raw[:20])#(1+1+2+2+2+1+1+2+4+4)

		self.version = version_hlen >> 4 #Left shift to shift version to lower bytes
		#minimum value of header length is 20 Bytes but we don't have sufficient bits we should multiply by 4 to get actual size
		self.ihl = (version_hlen & int('0b00001111',2)) 
		self.flags = flag_frag >> 13
		self.frag = (flag_frag & int('0b0001111111111111',2))#Last 13 bits for fragmentation
		self.src = Formatter.bytes_to_ip(src)
		self.dst = Formatter.bytes_to_ip(dst)

		return raw[(self.ihl*4):]#To do:Handle Options