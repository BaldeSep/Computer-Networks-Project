import socket, encoding

def validation(conn):
	packet_size = 1024
	
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
		command_input(conn, username)
	elif rejected == True:
		print ('You ran out of attempts')
		conn.close()
	


def command_input(conn, user_name):
	message_type = {'ascii-yes': bytes([1]),
					'ascii-no': bytes([2]),}
	packet_size = 1024
	
	ascii_amoring = conn.recv(packet_size)
	if ascii_amoring == message_type['ascii-yes']:
		print ('Yes to ascii amroing!!!')
	elif ascii_amoring == message_type['ascii-no']:
		print ('No to ascii amoring!!!')

	conn.close()
	
		
		

s = socket.socket()
host = '127.0.0.1'
port = int(input('Input a port number: '))




s.connect((host, port))

validation(s)	
	
s.close()





