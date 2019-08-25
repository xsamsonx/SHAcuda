import sys
import hashlib
import base58
from bitcoin import *
import locale




locale.setlocale(locale.LC_ALL, '')
BASE58 = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
number1 = 1
loops = 1000000000


for index in range (loops):

				sec = number1
				sec2 = base58.b58encode_int(sec)
				secret = sec2
				number = secret
				t = '%sAAAA' % number  #Here's the message/ suffix
				candHash = hashlib.sha256(t).digest()
				if candHash[0] == '\x00':
					print (secret)
					number1 += 1
					
									
				if not candHash[0] == '\x00':
					number1 += 1
					sec = number1
					sec2 = base58.b58encode_int(sec)
					secret = sec2
					number = secret
					t = '%sAAAA' % number  #Here's the message/ suffix
					candHash = hashlib.sha256(t).digest()