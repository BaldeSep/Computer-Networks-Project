import socket
from encoding_package.encoding_mod import encoder

def load_data_base(data_base):
	# Reads in all user data to be verified of the user
	f = open('auth.txt', 'r')

	raw_user_data = f.read().split(',')
	for i in range(len(raw_user_data)):
		raw_user_data[i] = raw_user_data[i].strip()
		user_name, password = raw_user_data[i].split(':')[0], raw_user_data[i].split(':')[1]
		
		data_base[user_name] = password
	
	f.close() 
	
def validate(conn):
	attempts_left = 3
	packet_size = 1024
	
	message_type = {'Invalid Credentials': bytes([1]), 
					'Valid Credentials': bytes([2]),
					'Reject': bytes([3])} 
					
	while attempts_left > 0:
		username = conn.recv(packet_size)
		username = username.decode('utf-8')
		password = conn.recv(packet_size)
		password = password.decode('utf-8')
		
		
		try:
			if data_base[username] == password:
				conn.send(message_type['Valid Credentials'])
				break
			else:
				attempts_left -= 1 
				if attempts_left == 0:
					conn.send(message_type['Reject'])
				else:
					conn.send(message_type['Invalid Credentials'])
		except KeyError:
				attempts_left -= 1 
				if attempts_left == 0:
					conn.send(message_type['Reject'])
				else:
					conn.send(message_type['Invalid Credentials'])
	
	if attempts_left > 0:
		session(conn)
	else:
		conn.close()




def server_wants_ascii_armoring():
	response = input('Do you want to apply ascii armoring? (y/n)?: ')
	if response == 'y':
		return True
	
	return False

def recieve_file_data(conn, ascii_armor, message_type, packet_size):
	
	dest_file = open('dest/file', 'wb')
	key_file = open('dest/key', 'rb')
	
	conn.send(message_type['size-?'])
	data_size = int.from_bytes(conn.recv(packet_size), 'big')
	conn.send(message_type['done'])
	
	conn.send(message_type['size-?'])
	total_size = int.from_bytes(conn.recv(packet_size), 'big')
	conn.send(message_type['done'])
	
	# Recieve data from client
	data = conn.recv(packet_size)
	while len(data) < (total_size):
		data = data + conn.recv(packet_size)
	
	# While client is not done sending data keep
	# processing incomming data
	while data != message_type['done'] and len(data) > 1:
		
		# Get key from key file
		key = key_file.read(packet_size)
		while len(key) < packet_size:
			key_file.seek(0,0)
			key = key_file.read(packet_size)
		
		# Get hash from processing function
		hash_, data = process_data(data, key, ascii_armor, data_size)
		
		
		attempts_left = 10
		# Check for integrity
		while hash_ != data[data_size:] and attempts_left > 0:
			attempts_left -= 1
			print('bad data')
			conn.send(message_type['bad data'])
			
			data = conn.recv(packet_size)
			while len(data) < total_size:
				data = data + conn.recv(packet_size)
			
			hash_, data = process_data(data, key, ascii_armor, data_size)
		
		data = data[:data_size]
		
		dest_file.write(data)
		
		# request to size of data before Base64 MIME encoding and added hash		
		conn.send(message_type['size-?'])
		data_size = int.from_bytes(conn.recv(packet_size), 'big')
		conn.send(message_type['done'])
		
		# request for size of data actually sent with added hash and Base64 Mime Encoding
		conn.send(message_type['size-?'])
		total_size = int.from_bytes(conn.recv(packet_size), 'big')
		conn.send(message_type['done'])
		
		print("Successful Transfer Of Data")
		
		# Recieve the next chunk of data
		print('Getting Next Chunk of Data from Client')
		data = conn.recv(packet_size)
		while len(data) < total_size:
			data = data + conn.recv(packet_size)
	
	conn.send(message_type['done'])
	
	dest_file.close()
	key_file.close()

def process_data(data, key, ascii_armor, data_size):
	e = encoder()
	# decode base 64 mime encoding if applied
	if ascii_armor == True:
		data = e.ascii_armor(data, 'd')
		
	# Decrypt data
	data = e.xor_c(data, key)
	
	# Get the hash from the data
	hash_ = data[data_size:]
	
	# Remove hash from data
	data = data[:data_size]

	print(len(data))

	# Recompute hash for comparison
	data = e.hash_(data)
	
	return hash_, data
	
def session(conn):
	packet_size = 2048	
	message_type = {'ascii-yes': bytes([1]),
					'ascii-no': bytes([2]),
					'ascii-?': bytes([3]),
					'bad data': bytes([4]),
					'err end comm': bytes([5]),
					'done': bytes([6]),
					'size-?': bytes([7]),}
	
	ascii_armor = False
	if conn.recv(packet_size) == message_type['ascii-?']:
		if server_wants_ascii_armoring() == True:
			conn.send(message_type['ascii-yes'])
			ascii_armor = True
		else:
			conn.send(message_type['ascii-no'])
	
	recieve_file_data(conn, ascii_armor, message_type, packet_size)
	
	conn.close()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# local host
host = '192.168.0.107'
port = int(input('Input a port number: '))
s.bind((host, port))

data_base = {}

load_data_base(data_base)

s.listen(1)
conn, addr = s.accept()

if validate(conn) == True:
	session(conn)
	

s.close()
	
