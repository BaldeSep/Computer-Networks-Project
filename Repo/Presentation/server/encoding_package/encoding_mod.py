import base64

class encoder():

	# XOR
	def xor_c(self, data, key):
		
		while len(key) < len(data):
			key = key + key
		
			
		encode_decode = bytearray()
		
		
		for byte in range(len(data)):
			encode_decode.append(data[byte] ^ key[byte])
			
		return encode_decode


	# Ascii Armor
	def ascii_armor(self, data, action = ''):
		if action == 'e':
			return base64.b64encode(data)
		elif action == 'd':
			return base64.b64decode(data)
		else:
			return 
		
	# Hashing data
	def hash_(self, data):
		data_size = len(data)
		sum_ = bytearray(data_size//8)
		for i in range(len(sum_)):
			sum_[i] = (data[i]^2 + data_size^3 + data[i]^4) % (256)

		return bytearray(data) + sum_





