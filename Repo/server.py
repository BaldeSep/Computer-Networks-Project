import socket, encoding

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
	message_type = {'send': '1', 'recv': '-1', 'valid': '0', 'invalid': '2'}
	
	packet_size = 1024
	conn.send((message_type['send']).encode('utf-8'))
	while attempts_left > 0:
		init = conn.recv(packet_size).decode('utf-8')
		if init == message_type['recv']:
			conn.send('user: '.encode('utf-8'))
			user_name = conn.recv(packet_size).decode('utf-8')
			
			conn.send('password: '.encode('utf-8'))
			password = conn.recv(packet_size).decode('utf-8')
			
			try:
				if data_base[user_name] == password:
					conn.send((message_type['valid']).encode('utf-8'))
					return True
				else:
					conn.send(message_type['invalid'].encode('utf-8'))
					attempts_left -= 1 
			except KeyError:
				conn.send(massage_type['invalid'].encode(''))
				attempts_left -= 1
			

def session(conn):
	packet_size = 1024
	ascii_armoring = input('Do you want ascii amoring?(y/n) ')
	if(ascii_armoring.lower == 'y'):
		pass
	else:
		pass
		


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# local host
host = '127.0.0.1'
port = int(input('Input a port number: '))
s.bind((host, port))

data_base = {}

load_data_base(data_base)

s.listen(1)
conn, addr = s.accept()

if validate(conn) == True:
	session(conn)
	

s.close()
	
