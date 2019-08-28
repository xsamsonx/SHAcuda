import sys
import hashlib
import base58
from bitcoin import *



BASE58 = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
number1 = 156135789162387962347843 #just random for testing
loops = 5120


for index in range (loops):

				sec = number1
				sec2 = base58.b58encode_int(sec)
				secret = sec2
				number = secret
				t = '%sAAAA' % number  #Here's the message/ suffix
				candHash = hashlib.sha256(t).digest()  #hashing number and message!!!
				if candHash[0] == '\x00':
					print (secret)  # just printing base58 of number!
					number1 += 1
					
									
				if not candHash[0] == '\x00':
					number1 += 1
					sec = number1
					sec2 = base58.b58encode_int(sec)
					secret = sec2
					number = secret
					t = '%sAAAA' % number  #Here's the message/ suffix
					candHash = hashlib.sha256(t).digest()