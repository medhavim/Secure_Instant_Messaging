# Secure Instant Chat Application, Server side.
# Medhavi Mahansaria, Naomi Joshi 

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
import os, sys, getopt, base64, pyDH, ConfigParser, csv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from fcrypt import *
import random, json



# users: list of (username, addr)
users = []

#list of (username, public_key)
pub_keys = []

#Remembering values
proof_hash = ''
last_REQSTART = ''


class ClientServerThread(threading.Thread):
    def __init__(self, ip, port, sock, server_public_key_file, server_private_key_file, users_info_file):
	threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
	global server_private_key
        server_private_key = Load_RSA_PrivateKey(server_private_key_file)
	global server_public_key
        server_public_key = Load_RSA_PublicKey(server_public_key_file)
        self.all_users = self._load_users_info(users_info_file)
        self.login_users = dict()
	global dhServer
	dhServer = pyDH.DiffieHellman()
	dhServer.pub_key = dhServer.gen_public_key()
	self.sock = sock 
	print "[+] New thread started for " + ip + " : " + str(port)

    @staticmethod
    def _load_users_info(users_info_file, delimiter=',', quotechar='|'):
        users_info = dict()
        with open(users_info_file, 'rb') as csv_file:
            rows = csv.reader(csv_file, delimiter=delimiter, quotechar=quotechar)
            for row in rows:
                username = row[0]
                salt_and_hash = (row[1], row[2])
                users_info[username] = salt_and_hash
        return users_info

    def run(self):
	while(1):
                #recive msg
                data, addr = self.sock.recvfrom(65507)
                data = json.loads(data.decode())
                print(data['type'], data, addr)
                print('\n')
                #msg type
                if(data['type'] == 'Login' and :
			#Give user a challenge
				
                        user = (data['username'].encode(), addr)
                        pubkey_find = False
                        pubkey = retrieve_pubkey(user[0])
                        if(pubkey_find is None):
                                print('Server does not have public_key of ' + user[0])
                        else:
                                users.append(user)

                #elif(data['type'] == 'REQSTART'):
                #       authenticate_talkto(s, addr, 2, data)

                #elif(data['type'] == 'PROOFBACK'):

def createSocket(ip, port):
        try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except socket.error as msg:
                s = 'None'

        try:
                s.bind((ip, port))
        except socket.error as msg:
                s.close
                s = 'None'

        #exception handling
        if s is None:
                print('Could not initialize server, try again.')
                sys.exit(1)

        print('Server is Listening on Port: ', port)
        return s


def main():
	config = ConfigParser.RawConfigParser()
    	config.read('conf/server.cfg')
	server_port = config.getint('info', 'port')
	server_ip = config.get('info', 'ip')
    	server_private_key_file = config.get('info', 'private_key')
  	server_public_key_file = config.get('info', 'public_key')
    	user_creds = config.get('info', 'user_creds')

	sock = createSocket(server_ip, server_port)
	threads = []

	#listening for incoming connections
	while True:
		sock.listen(4)
		print "\nListening for incoming connections..."
		(clientSock, (client_ip, client_port)) = sock.accept()
		print 'client_ip: ' + str(client_ip)
		print 'cline_port: ' + str(client_port)
		newthread = ClientServerThread(client_ip, client_port, clientSock, server_public_key_file, server_private_key_file, user_creds)
		newthread.start()
		threads.append(newthread)

	#handling client threads
	for t in threads:
		t.join()

	sock.close()


if __name__ == "__main__":
	main()
