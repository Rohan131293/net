from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
import struct

class Raw(Layer):
	@staticmethod
	def help():

		print('\nrawLayer = Raw(load = "Raw Data")')

		print('\n#Methods:\n1)encoded = Raw().encode() : Returns encoded data')
		print('2)remData = Raw().decode(raw,blen=-1) : Extracts blen bytes of data')
		print('3)Raw().show() : Displays parameters')
		print('4)Raw.help() : Displays this message')

	def __init__(self,load = ""):
		self.load=load

	def	show(self):
		print('#Raw Layer:\nload = {}\n'.format(self.load))

	def	summary(self):
		print('#Raw Layer: Payload-> {}'.format(self.load))

	def encode(self):
		encoded = Formatter.load_to_bytes(self.load)
		return encoded

	def decode(self,raw,blen=-1):
		if(blen<0):#Entire Input Raw Data
			self.load=Formatter.bytes_to_load(raw)
			return ''
		else:#Requested Bytes of Input Raw Data
			self.load=Formatter.bytes_to_load(raw[:blen])
			return raw[blen:]
