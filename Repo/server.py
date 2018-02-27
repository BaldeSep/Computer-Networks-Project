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
	packet_size = 1024
	
	message_type = {'Invalid Credentials': bytes([1]), 
					'Valid Credentials': bytes([2]),
					'Reject': bytes([3])} 
					
	while attempts_left > 0:
		username = conn.recv(packet_size).decode('utf-8')
		password = conn.recv(packet_size).decode('utf-8')
		
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

def session(conn):
	message_type = {'ascii-yes': bytes([1]),
					'ascii-no': bytes([2]),}
	
	packet_size = 1024
	
	ascii_amoring = input('Do you want ascii amoring?(y/n)?: ')
	if ascii_amoring == 'y':
		conn.send(message_type['ascii-yes'])
	else:
		conn.send(message_type['ascii-no'])
		
	conn.close()
		


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
	
