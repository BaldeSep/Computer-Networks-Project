import socket, encoding

def validation(s):
	packet_size = 1024
	message_type = {'send': '1', 'recv': '-1', 'valid': '0', 'invalid': '2'}
	while True:
		init = s.recv(packet_size).decode('utf-8')
		# We are going to accept a message
		# Otherwise we are sending data
		if init == message_type['send']:
			# if you wanna send me data 
			# I'm telling you I wanna recieve data
			s.send(message_type['recv'].encode('utf-8'))
			
			user_prompt = s.recv(packet_size).decode('utf-8')
			user_name = input(user_prompt).encode('utf-8')
			s.send(user_name)
			
			password_prompt = s.recv(packet_size).decode('utf-8')
			password = input(password_prompt).encode('utf-8')
			s.send(password)
			
			response = s.recv(packet_size).decode('utf-8')
			if response == message_type['valid']:
				command_input(s, user_name.decode('utf-8'), packet_size)
				return
			elif response == message_type['invalid']:
				s.send(message_type['recv'].encode('utf-8'))
			elif response == message_type['out']:
				return
			
			 
		

def command_input(conn, user_name, packet_size):
	pass
		

s = socket.socket()
host = '127.0.0.1'
port = int(input('Input a port number: '))




s.connect((host, port))

validation(s)	
	
s.close()





