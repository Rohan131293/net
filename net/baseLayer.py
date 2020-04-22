from __future__ import print_function
from utility.LogConfig import *
import struct

#B unsigned char : 1 byte
#H unsigned short size:2 bytes
#L unsigned long : 4 bytes
#s char[] byte size : 1 byte per element

class Layer:
	@staticmethod
	def help():
		print("Layer : No help method available with me :(");
	def __init__(self):
		pass
	def show(self):	
		print("{} : No show method available with this class :(".format(self.__class__.__name__))
	def summary(self):
		print("{} : No summary method available with this class :(".format(self.__class__.__name__))
	def encode(self):
		print("{} : No encode method available with this class :(".format(self.__class__.__name__))	
	def decode(self,raw):
		print("{} : No decode method available with this class :(".format(self.__class__.__name__))
		return None
		
	@staticmethod
	def calculate_checksum(self,raw_data,checksum_position=0):
		padding=struct.pack('!B',0)
		data_len=len(raw_data)
		while(data_len%4!=0):#Add Padding if there are odd number of octet
			raw_data=raw_data+padding
			data_len=len(raw_data)
		field_list=[ (struct.unpack('!H',
			raw_data[iterator:(iterator+2)]))[0] for iterator in range(0,data_len,2)]
		field_list[checksum_position]=0#checksum_field
		field_sum=sum(field_list)
		while field_sum > 0xFFFF:#Make sure field sum is 16 bit only
	 		field_sum=(field_sum & 0xFFFF)+(field_sum >> 16)
		return 0x10000+(~field_sum)
		
