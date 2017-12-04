# Secure Instant Chat Application, Client.
# Medhavi Mahansaria, Naomi Joshi

import random
import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac, serialization
import os, sys, getopt, base64, pyDH, ConfigParser, cmd, getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time, json
from fcrypt import *

shared_keys_database = []
auth_users = []

server_addr = ('127.0.0.1', 8000)

#remembering values
last_PUBKEY = ''
last_REQSTART = ''
last_STARTTALKAUTH = ''
last_CONTINUETALKAUTH = ''

MAX_RETRY_LOGIN_TIMES = 3

class ChatClient(cmd.Cmd):
    def __init__(self, ip, port, pub_key_file):
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock = None
        
	# user name for this chat client
        self.user_name = None
        
	# Properties of users authentication
	self.loggedIn = False
	#self.authenticated = False
		
	# chat server ip, port and public key
        self.server_ip = ip
        self.server_port = port
        self.server_pub_key = Load_RSA_PublicKey(pub_key_file)
        
	# generate rsa key pair
        self.rsa_pri_key, self.rsa_pub_key = Generate_RSA_key_pair()
        
	# generate dh key pair
        self.dhClient = pyDH.DiffieHellman()
	self.dh_pub_key = self.dhClient.gen_public_key()
	self.dh_pri_key = self.dhClient.get_private_key()
        
		# shared dh key
        self.shared_dh_key = None
        
		# chat client ip and port, used to receive messages
        self.client_ip = '127.0.0.1'
        self.client_port = random.randint(1025,9999)
	
		# online-users known to the chatclient
        self.online_list = dict()
        
		# start socket for receiving messages
        self.conn = self.createSocket(self.client_ip, self.client_port)
       
		#thread1: always available to send msg to server
        thread1 = threading.Thread(target=self.SendMessage, args = (self.conn,))
        thread1.start()

        #thread2: always ready to receive an INCOMING msg from server
        #self.thread2 = threading.Thread(target=self.ListenForMessage, args = (self.conn,))
        #thread2.start() 
	
		# start commandline interactive mode
        cmd.Cmd.__init__(self)

    def createSocket(self, ip, port):
        try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            	#sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except socket.error as msg:
            	sock = 'None'

        try:
            	sock.bind((ip, port))
        except socket.error as msg:
            	sock.close
            	sock = 'None'

        #exception handling
        if sock is None:
            	print('Could not initialize client, try again.')
            	sys.exit(1)

	print("Client is ready ", sock.getsockname())
        return sock


    
    # --------------------------- login to the server ------------------------- #
    def SendMessage(self, conn):
	if not self.loggedIn:
		print 'SendMessage: if not'
		login_times = 0
        	while login_times < MAX_RETRY_LOGIN_TIMES and not self.loggedIn:
            		self.loggedIn, user_name = self._auth_to_server()
           		login_times += 1
           		if self.loggedIn:
               			self.user_name = user_name
               			chat_client.prompt = self.user_name + CMD_PROMPT
               			chat_client.cmdloop('###### User <' + user_name + '> successfully login')
       		if not self.loggedIn:
       			print 'Your retry times has exceeded the maximum allowed times, exit the program!'
           		self.recv_sock.close()
       			os._exit(0)

	if self.loggedIn:
		print 'SendMessage: if'
		while(1):
			msg = raw_input('')

			if(msg.startswith('list')):
				data = {'type': 'list', 'username' :self.username}
				conn.sendto(json.dumps(data).encode(), (self.server_ip, self.server_port))

    def _auth_to_server(self):
        user_name = raw_input('Please input your user name: ')
       	password = getpass.getpass('Please input your password: ')
	login_result = False
       	self.username = user_name
	#data = {'type': 'Login', 'username':self.username, 'password': password}
        #self.conn.sendto(json.dumps(data).encode(), (self.server_ip, self.server_port))
       	try:
        	self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        	self.client_sock.connect((self.server_ip, self.server_port))
            
		# Step 1: initiate the authentication to server
	        auth_init_response = self._auth_init()
		solved_challenge = self._handle_auth_init_response(auth_init_response)
            
		# Step 2: send authentication start message(including user name, password, etc.) to the server c1_nonce, auth_start_response = self._auth_start(solved_challenge, user_name, password)
		auth_result, self.shared_dh_key, c2_nonce = self._handle_auth_start_response(c1_nonce, auth_start_response)
            
		# Step 3: send authentication confirmation message back to the server,
            	# which is c2_nonce encrypted with dh_shared key
            	if auth_result and self._auth_end(c2_nonce):
                	login_result = True
        except socket.error:
            	print 'Cannot connect to the server in the authentication process, exit the program!'
            	os._exit(0)
        except:
            	print 'Unknown error happens when trying to login: ', sys.exc_info()[0], ', please retry!'
        finally:
            	if not login_result:
                	self.client_sock.close()
            	return login_result, user_name

    def _auth_init(self):
	login_msg = {'type': 'Login', 'username':self.username, 'password': password}
       	#self.client_sock.sendall(login_msg)
       	self.client_sock.sendto(json.dumps(login_msg).encode(), (self.server_ip, self.server_port))
        login_response = self.client_sock.recv(MAX_MSG_SIZE)
       	return login_response
	
def main():
	config = ConfigParser.RawConfigParser()
    	config.read('conf/client.cfg')
    	server_port = config.getint('server_info', 'port')
    	server_ip = config.get('server_info', 'ip')
    	server_public_key_file = config.get('server_info', 'public_key')
    	chat_client = ChatClient(server_ip, server_port, server_public_key_file)
    	#chat_client.login()
    	chat_client.conn.close()

if __name__ == "__main__":
	main()


