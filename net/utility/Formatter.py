from __future__ import print_function
from LogConfig import *
import binascii
import socket
import sys
import os

class Formatter:
	
	python_version=sys.version.split(' ')[0] >'3'
	#To-Do: Validation is to be added for IP and MAC
	@staticmethod
	def help():
		print('Class Name : Formatter\n#Helper Functions:')
		print('1)bytes_to_mac(bytes_addr)')
		print('2)mac_to_bytes(str_addr)')
		print('3)bytes_to_ip(bytes_addr)')
		print('4)ip_to_bytes(str_addr)')
		print('5)load_to_bytes(message)')
		print('6)print_in_hex(byteStr)')
		print('7)printStruct(blockList,spacePerBit=9)')

	@staticmethod
	def bytes_to_mac(bytes_addr):
		mac_str=binascii.hexlify(bytes_addr)
		if(Formatter.python_version):
			mac_str=str(mac_str)[2:-1]
		mac_list=[mac_str[(i-2):i] for i in range(2,13,2)]
		mac_addr=':'.join(mac_list)
		return mac_addr.upper()
	
	@staticmethod
	def mac_to_bytes(str_addr):
		mac_addr=binascii.unhexlify(str_addr.replace(':',''))
		return mac_addr
	
	@staticmethod
	def bytes_to_ip(bytes_addr):
		ip_addr=socket.inet_ntoa(bytes_addr)
		return ip_addr
	
	@staticmethod
	def ip_to_bytes(str_addr):
		ip_addr=socket.inet_aton(str_addr)
		return ip_addr

	@staticmethod
	def load_to_bytes(message):
		list_hex = map(lambda x: hex(ord(x))[2:] ,str(message))
		list_fix = [ '0'+iterator if len (iterator) == 1 else iterator  for iterator in list_hex]
		list_conv = map(binascii.unhexlify,list_fix)
		bytes_load = ''.join(list_conv)
		return (bytes_load)

	@staticmethod
	def bytes_to_load(bytes_message):
		str_message = binascii.hexlify(bytes_message)
		list_bytes=[]

		def bytes_to_str(input_char):
			temp=chr(int(input_char,16))
			if(temp in string.printable):
				return temp
			return '\\x'+input_char

		try:
			list_bytes = [ str_message[i:i+2]for i in range (0,len(str_message),2)]
			list_str = map(lambda x : bytes_to_str(x) ,list_bytes)
			return ''.join(list_str)
		except:
			logging.error('Could not Parse')

	@staticmethod
	def print_in_hex(byteStr):
		print(''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip())

	@staticmethod
	def printStruct(blockList,spacePerBit=9):

		def space(length):
			for i in range(0,length):
				print(' ',end='')
		
		def print_line(spacePerBit):
			print('|',end='')
			length=(spacePerBit*8)-2
			for i in range(0,length):
				print('-',end='')
			print('|')

		def first_line(spacePerBit):
			length=(spacePerBit*8)-2
			print('\n.',end='')
			for i in range(0,length):
				print('-',end='')
			print('.')

		def print_block(bName,availableSpace):
			#Chopping of the Name for the sake of Simplycity
			#To-do:Support Multiline bName
			availableSpace=availableSpace-2
			if(len(bName)>availableSpace):
				bName=bName[:availableSpace]
			bNameLength=len(bName)
			prePrint=((availableSpace-bNameLength)/2)
			postPrint=prePrint
			if((bNameLength+availableSpace)%2!=0):
				postPrint+=1
			print('|',end='')
			space(prePrint)
			print(bName,end='')
			space(postPrint)
			print('|',end='')

		if(type(blockList)!=list):
			logging.error('Received '+str(type(blockList))+'\nExpecting List of dictionary e.g. blockList=[{"Name":4},{"Id":4}]')
			return
		
		if(len(blockList)==0):
			logging.error('Received empty blockList')
			return

		#spacePerBit should be odd for proper display
		if(spacePerBit%2==0):
			spacePerBit+=1

		(rows, columns) = os.popen('stty size', 'r').read().split()

		while(int(columns)<(spacePerBit*8)):
			spacePerBit-=2

		print()
		#Printing Numbers
		for i in range (8,0,-1):
			space(spacePerBit/2)
			print(i,end='')
			space(spacePerBit/2)
		
		index=0
		first_line(spacePerBit)
		for block in blockList:
			if(type(block)!=dict):
				logging.error('Received '+type(block)+', expecting dictionary')
				return


			if(len(block)!=1):
				logging.error('Expected size of dictionary is 1')
				return
			

			[(name,bits)]=block.items()
			maxExpectedBits=8-(index%8)
			if(maxExpectedBits==8):
				#For multibyte partial blocks
				if(bits>8 and (bits%8)!=0):
					logging.error('No Support for multibyte partial block. Manually split the block')
					logging.info('Support for multibyte with order of 8 is available')
					return

			elif(bits>maxExpectedBits):
				logging.error('No support for Structre extending across multiple bytes. Manually split the block')
				return


			while(bits>0):
				availableSpace=0
				if(bits>8):
					availableSpace=(spacePerBit*8)
					bits=bits-8
					index=index+8
				else:
					availableSpace=(spacePerBit*bits)
					index=index+bits
					bits=0
				print_block(name,availableSpace)
				name=''
				if((index%8)==0):
					print()
					if(bits==0):
						print_line(spacePerBit) 
		print()
		if((index%8)!=0):
			logging.warning('Incomplete Structure')