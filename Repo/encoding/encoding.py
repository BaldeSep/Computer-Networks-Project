import base64

def key_is_shorter_than_text(text, key):
	return (len(key) < len(text))

# XOR Cipher
def xor_c(text, key):
	
	while(key_is_shorter_than_text(text, key) == True):
		key += key
		
	encode_decode = bytearray('', encoding = 'utf-8')
	
	for (byte_of_text, byte_of_key) in zip(text, key):
		encode_decode.append(byte_of_text ^ byte_of_key)
		
	return encode_decode


# Ascii Armor
def ascii_armor(text, action = ''):
	if action == 'encode':
		return base64.b64encode(text)
	elif action == 'decode':
		return base64.b64decode(text)
	else:
		return 
	

def hash_(text, modulus):
	sum_ = 0
	for i in range(len(text)):
		sum_ += text[i]

	text.append(sum_ % modulus)





