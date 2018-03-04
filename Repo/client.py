import socket
import base64
from getpass import getpass
from tkinter import filedialog
from encoding_package.encoding_mod import encoder


# Validate Client Information
def validation(conn):
	# Packet Size Set To 2KB
	packet_size = 2048
	
	# Basic Protocol Used For The Client And The Server To Talk
	message_type = {'Invalid Credentials': bytes([1]), 
					'Valid Credentials': bytes([2]),
					'Reject': bytes([3])}
	
	signed_in = False
	rejected = False
	
	try:
		while signed_in == False and rejected == False:
			# Ask for username
			username = input('user: ')
			conn.send(username.encode('utf-8'))
			
			# Ask for user password
			password = getpass('password: ')
			conn.send(password.encode('utf-8'))
			
			# Get Response From Server
			response = conn.recv(packet_size)
			if response == message_type['Valid Credentials']:
				signed_in = True
			elif response == message_type['Invalid Credentials']:
				print ('Permission denied, try again.')
			elif response == message_type['Reject']:
				rejected = True
	except:
		print ("ERROR: CONNECTION WILL NOW TERMINATE.")
		conn.close()
			
	if signed_in == True:
		print ('You are signed in!!!')
		session(conn, username)
	elif rejected == True:
		print ('Permission denied')
		conn.close()
	
def send_server_file(conn, ascii_armor, message_type, packet_size):
	src_filename = filedialog.askopenfilename(title='Open Source File')
	key_filename = filedialog.askopenfilename(title='Open Key File')
	
	src_file = open(src_filename, 'rb')
	key_file = open(key_filename, 'rb')
	
	# Read Some data from the source file
	data = src_file.read(2**20)
	
	# Creates an encoder object to handle encoders
	e = encoder()
	try:
		# Sends size of data chunk prior to encoding and hashing
		response = conn.recv(1)
		if response == message_type['size-?']:
			conn.send( bin(len(data)).encode() )
		conn.recv(1)
		
		# Begin sending data to the server
		while len(data) > 0:	
			# Hash the data
			data = e.hash_(data)
			
			# Get a key from the key file
			key = key_file.read(packet_size)
			if len(key) <= packet_size:
				key_file.seek(0,0)
		
			# Encrypt the data using XOR method
			data = e.xor_c(data, key)
			
			
			# If Ascii Armoring is requested apply it to the data chunk
			if ascii_armor == True:
				data = e.ascii_armor(data, 'e')
			
			# Send size of data after base 64 MIME encoding and adding hash to data
			response = conn.recv(1)
			if response == message_type['size-?']:
				conn.send( bin(len(data)).encode() )
				conn.recv(1)
			
			# Send the data
			try:
				if conn.sendall(data) == None:
					print('Successfully Sent Data')
			except:
				print ('Error could not send data')

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
			data = src_file.read(2**20)
			
			# Send the size of the data prior to encoding and hashing
			if response == message_type['size-?']:
				print('Sending Size')
				conn.send( bin(len(data)).encode() )
				print('Done Sending Size')
			
			print('DONE')	
			conn.recv(1)
		else:
			# Once done send a done message
			conn.send(message_type['done'])
	except:
		print ('ERROR: CONNECTION WILL NOW TERMINATE.')
		conn.close()
	
	
	# Closes files
	src_file.close()
	key_file.close()
	
def session(conn, user_name):
	packet_size = 4096
	
	message_type = {'ascii-yes': bytes([1]),
					'ascii-no': bytes([2]),
					'ascii-?': bytes([3]),
					'bad data': bytes([4]),
					'err end comm': bytes([5]),
					'done': bytes([6]),
					'size-?': bytes([7]),}
	
	ascii_armor = False
	try:
		conn.send(message_type['ascii-?'])
		if conn.recv(packet_size) == message_type['ascii-yes']:
			ascii_armor = True
		
		send_server_file(conn, ascii_armor, message_type, packet_size)
		conn.close()	
	except:
		print ("ERROR: CONNECTION WILL NOW TERMINATE.")
		

# Create Socket
s = socket.socket()

# Get Host IP To Send Data To
host = input('Input a host IP: ')

if host == '':
	host = '127.0.0.1'

# Enter A Port Number On The Host Computer To Send Data To
port = int(input('Input a port number: '))

# Estanblish Connection Between The Host And The Port
s.connect((host, port))

# Enter Validation Stage
validation(s)	
	
# Close Connection After Sending Data To Server
s.close()





