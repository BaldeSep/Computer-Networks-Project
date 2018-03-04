import socket
import base64
from encoding_package.encoding_mod import encoder



def validation(conn):
	packet_size = 2048
	
	message_type = {'Invalid Credentials': bytes([1]), 
					'Valid Credentials': bytes([2]),
					'Reject': bytes([3])}
	
	
	signed_in = False
	rejected = False
	
	while signed_in == False and rejected == False:
		# Ask for username
		username = input('user: ')
		conn.send(username.encode('utf-8'))
		
		# Ask for user password
		password = input('password: ')
		conn.send(password.encode('utf-8'))
		
		response = conn.recv(packet_size)
		if response == message_type['Valid Credentials']:
			signed_in = True
		elif response == message_type['Invalid Credentials']:
			print ('Invalid Credentials')
		elif response == message_type['Reject']:
			rejected = True
			
	if signed_in == True:
		print ('You are signed in!!!')
		session(conn, username)
	elif rejected == True:
		print ('You ran out of attempts')
		conn.close()
	
def send_server_file(conn, ascii_armor, message_type, packet_size):
	src_file = open('src/file', 'rb')
	key_file = open('src/key', 'rb')
	
	# Read Some data from the source file
	data = src_file.read(packet_size//2)
	
	# Creates an encoder object to handle encoders
	e = encoder()
	
	response = conn.recv(1)
	if response == message_type['size-?']:
		conn.send( (len(data)).to_bytes(2, 'big') )
	conn.recv(1)
	
	# Begin sending data to the server
	while len(data) > 0:	
		# Hash the data
		data = e.hash_(data)
		
		# Get a key from the key file
		key = key_file.read(packet_size)
		while len(key) < packet_size:
			key_file.seek(0,0)
			key = key_file.read(packet_size)
	
		# Encrypt the data using XOR method
		data = e.xor_c(data, key)
		
		
		# If Ascii Armoring is requested apply it to the data chunk
		if ascii_armor == True:
			data = e.ascii_armor(data, 'e')
		
		# Send size of data after base 64 MIME encoding and adding hash to data
		response = conn.recv(1)
		if response == message_type['size-?']:
			conn.send( (len(data)).to_bytes(2, 'big') )
			conn.recv(1)
		
		# Send the data
		try:
			if conn.sendall(data) == None:
				print('Successfully Sent Data')
		except:
			print('Error could not send data')

		# Check to see if the data sent was properly recieved
		response = conn.recv(1)
		while response == message_type['bad data']:
			# send the data again
			try:
				if conn.sendall(data) == None:
					print('Successfully Sent Data')
			except:
				print('Error could not send data')
			
			print('BAD DATA')
			
			# Check again if the data was good
			response = conn.recv(1)
		
		# If too many errors happened end connection
		if response == message_type['err end comm']:
			break	
		
		# Gather the next chunk of data
		data = src_file.read(packet_size//2)
		
		if response == message_type['size-?']:
			print('Sending Size')
			conn.send( (len(data)).to_bytes(2, 'big') )
			print('Done Sending Size')
		
		print('DONE')	
		conn.recv(1)
	else:
		# Once done send a done message
		conn.send(message_type['done'])

	
	
	# Closes files
	src_file.close()
	key_file.close()
	
def session(conn, user_name):
	packet_size = 2048
	
	message_type = {'ascii-yes': bytes([1]),
					'ascii-no': bytes([2]),
					'ascii-?': bytes([3]),
					'bad data': bytes([4]),
					'err end comm': bytes([5]),
					'done': bytes([6]),
					'size-?': bytes([7]),}
	
	ascii_armor = False
	conn.send(message_type['ascii-?'])
	if conn.recv(packet_size) == message_type['ascii-yes']:
		ascii_armor = True
	
	send_server_file(conn, ascii_armor, message_type, packet_size)
	conn.close()	
		

s = socket.socket()
host = '192.168.0.107'
port = int(input('Input a port number: '))




s.connect((host, port))

validation(s)	
	
s.close()





