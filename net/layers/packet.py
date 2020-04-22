from __future__ import print_function
from net.utility.LogConfig import *
from net.utility.Formatter import Formatter
from net.baseLayer import Layer
import struct

class Packet(Layer):
	@staticmethod
	def help():
		print('p=Packet(Ether(src="AA:BB:CC:DD:EE:FF",dst="FF:FF:FF:FF:FF:FF"),ARP(hwsrc="AA:BB:CC:DD:EE:FF",psrc="192.168.1.1",pdst="192.168.1.2"))')

		print('\n#Methods:\n1)encoded = Packet().encode(): Returns encoded Packet')
		print('2)remData = Packet().decode(raw): Decodes parameter from given raw data')
		print('3)Packet().show(): Displays parameters')
		print('4)Packet.help(): Displays this message')

	def __init__(self,*layer):
		self.layers=list(layer)

	def	show(self):
		for iterator in self.layers:
			iterator.show()

	def	summary(self):
		for iterator in self.layers:
			iterator.summary()

	