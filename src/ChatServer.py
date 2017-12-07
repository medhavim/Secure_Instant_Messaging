import base64
import ConfigParser
import Crypto
import csv
import json
import os
import pickle
import socket
import threading
import time
import traceback
from Message import MessageStatus, AuthMsg, UserListRes, UserInfoRes, LogoutRes, LINE_SEPARATOR, SPACE_SEPARATOR, MAX_BUFFER_SIZE


# MSS = 1460


class UserState(object):
    INIT = 0,
    VERIFIED = 1,
    AUTHENTICATED = 2


class UserInfo:
    def __init__(self, challenge):
        self.state = UserState.INIT
        self.challenge = challenge
        self.rsa_pub_key = None
        self.secret_key = None
        self.user_name = ''
        self.ip = ''
        self.port = ''
        self.temp_nonce = ''


class Server:
    def __init__(self, host, port, private_key_file, users_file):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.private_key = Crypto.load_private_key(private_key_file)
        self.all_users = self.read_userInfo(users_file)
        self.users_loggedin = dict()

    @staticmethod
    def read_userInfo(users_info_file, delimiter=';', charQuote='|'):
        user_dict = dict()
        with open(users_info_file, 'rb') as csv_file:
            rows = csv.reader(csv_file, delimiter=delimiter, quotechar=charQuote)
            for row in rows:
                salt, hash = (row[1], row[2])
                username = row[0]
                user_dict[username] = (salt, hash)
        return user_dict

    def client_handler(self, connection, client_addr):
        try:
            while True:
                msg = connection.recv(MAX_BUFFER_SIZE)
                if not msg:
                    break
                msg = json.loads(msg)
                msg_type = msg['type']
                data = msg['data']
                # establishing authentication init message
                if msg_type == MessageStatus.INIT and client_addr not in self.users_loggedin:
                    print 'Authentication init message received from ', client_addr
                    self.client_handler_for_init(connection, client_addr)
                # establishing authentication start message
                elif msg_type == MessageStatus.START_AUTH and client_addr in self.users_loggedin \
                        and self.users_loggedin[client_addr].state == UserState.INIT:
                    print 'Authentication start message received from ', client_addr
                    isUserVerified, encrypted_response_to_client = self.client_handler_for_auth_start(client_addr, data)
                    msg = dict()
                    msg['data'] = encrypted_response_to_client
                    if not isUserVerified:
                        msg['type'] = MessageStatus.INVALID_RES
                        connection.sendall(json.dumps(msg))
                        self.client_error_handler(connection, client_addr)
                        break
                    msg['type'] = MessageStatus.VALID_RES
                    connection.sendall(json.dumps(msg))
                # establishing authentication end message
                elif msg_type == MessageStatus.END_AUTH and client_addr in self.users_loggedin \
                        and self.users_loggedin[client_addr].state == UserState.VERIFIED:
                    print 'Authentication end message received from ', client_addr
                    isAuthEstablished, encrypted_response_to_client = self.client_handler_for_auth_end(client_addr, data)
                    if not isAuthEstablished:
                        msg = dict()
                        msg['type'] = MessageStatus.INVALID_RES
                        msg['data'] = encrypted_response_to_client
                        connection.sendall(json.dumps(msg))
                        self.client_error_handler(connection, client_addr)
                        break
                    self.users_loggedin[client_addr].state = UserState.AUTHENTICATED
                    print 'Successfully logged in user: ', self.users_loggedin[client_addr].user_name
                    self.send_encrypted_data_to_client(connection, self.users_loggedin[client_addr],
                                                       encrypted_response_to_client, False)
                # message exchange between authenticated users
                elif client_addr in self.users_loggedin and \
                                self.users_loggedin[client_addr].state == UserState.AUTHENTICATED:
                    iv, response_from_client = data.split(LINE_SEPARATOR)
                    user_dict = self.users_loggedin[client_addr]
                    decrypted_response_from_client = Crypto.symmetric_decryption(user_dict.secret_key,
                                                             Crypto.asymmetric_decryption(self.private_key, iv),
                                                             response_from_client)
                    # sending response for list message
                    if msg_type == MessageStatus.LIST:
                        print 'Received LIST request message from ', client_addr
                        self.client_handler_for_list(user_dict, connection, decrypted_response_from_client)
                    # handle get user info message
                    elif msg_type == MessageStatus.TICKET_TO_USER:
                        print 'Received get user information message from ', client_addr
                        self.client_handler_for_loggedUsersInfo(user_dict, connection, decrypted_response_from_client)
                    # handle logout message
                    elif msg_type == MessageStatus.LOGOUT:
                        print 'Received logout message from ', client_addr
                        self.logout_handler(user_dict, client_addr, connection, decrypted_response_from_client)
                    else:
                        print 'Illegal message type: ', msg_type
        except:
            print 'Error happens when handling client messages, break the connection!'
            self.client_error_handler(connection, client_addr)
        finally:
            print 'Close the connection with ' + str(client_addr)
            connection.close()

    # --------------------------- establishin login and authentication ------------------------- #
    def client_handler_for_init(self, connection, client_addr):
        challenge, challenge_hash, truncated_challenge = self.generate_challenge()
        connection.sendall(str(truncated_challenge) + LINE_SEPARATOR + challenge_hash)
        user_dict = UserInfo(str(challenge))
        self.users_loggedin[client_addr] = user_dict

    def client_handler_for_auth_start(self, client_address, data):
        index = data.find(LINE_SEPARATOR)
        if index != -1:
            challenge = data[0:index].strip()
            msg = data[index:].strip()
        else:
            challenge = ''
            msg = ''
        response_from_client = pickle.loads(Crypto.asymmetric_decryption(self.private_key, msg))
        # check if the response given to the challenge is correct
        if challenge != self.users_loggedin[client_address].challenge:
            return False, 'Response to the given challenge is incorrect!'
        user_name = response_from_client.user_name
        # the same user cannot login twice
        user_dict = self.find_user_by_name(user_name)
        if user_dict is not None and user_dict.state == UserState.AUTHENTICATED:
            return False, 'User is already logged in, please logout and retry!'
        password = response_from_client.password
        if not self.check_password(user_name, password):
            return False, 'The user name or password is wrong!'
        # set user information
        current_user = self.users_loggedin[client_address]
        current_user.user_name = response_from_client.user_name
        current_user.ip = response_from_client.ip
        current_user.port = int(response_from_client.port)
        current_user.rsa_pub_key = Crypto.deserialize_pub_key(response_from_client.rsa_pub_key)
        current_user.state = UserState.VERIFIED
        # DH key exchange
        dh_pri_key, dh_pub_key = Crypto.generate_dh_key_pair()
        current_user.secret_key = Crypto.generate_shared_dh_key(dh_pri_key,
                                                            Crypto.deserialize_pub_key(response_from_client.dh_pub_key))
        # compose response message
        n1 = response_from_client.n1
        n2 = Crypto.generate_nonce(32)
        current_user.temp_nonce = n2
        serialized_dh_pub_key = Crypto.serialize_pub_key(dh_pub_key)
        response_to_client = pickle.dumps(AuthMsg('','','',serialized_dh_pub_key, '','',n1, n2), pickle.HIGHEST_PROTOCOL)
        encrypted_response_to_client = Crypto.asymmetric_encryption(current_user.rsa_pub_key, response_to_client)
        return True, encrypted_response_to_client

    def check_password(self, user_name, password):
        if user_name not in self.all_users:
            return False
        salt, pwd_hash = self.all_users[user_name]
        if Crypto.generate_hash(password, salt) != pwd_hash:
            return False
        return True

    def client_handler_for_auth_end(self, client_address, data):
        user_dict = self.users_loggedin[client_address]
        iv, encrypted_n2 = data.split(LINE_SEPARATOR)
        received_n2 = Crypto.symmetric_decryption(user_dict.secret_key,
                                                     Crypto.asymmetric_decryption(self.private_key, iv),
                                                     encrypted_n2)
        if received_n2 != str(user_dict.temp_nonce):
            return False, 'The nonce encrypted with the session key is wrong!'
        end_response_to_client = str(long(received_n2) + 1)
        return True, end_response_to_client

    # --------------------------- sending all logged in users to authenticated clients --------------------------- #
    def client_handler_for_list(self, request_user_info, connection, received_list_message):
        list_flag, list_send_time = received_list_message.split(LINE_SEPARATOR)
        if self.validate_timestamp_in_req(connection, list_send_time):
            current_user_names = SPACE_SEPARATOR.join(user.user_name for client_addr, user in self.users_loggedin.iteritems())
            user_list_res = UserListRes(current_user_names)
            self.send_encrypted_data_to_client(connection, request_user_info, user_list_res)

    # --------------------------- send ticket to other clients for client-to-client authentication------------------------- #
    def client_handler_for_loggedUsersInfo(self, request_user_info, connection, user_info_msg):
        target_user_name, send_time = user_info_msg.split(LINE_SEPARATOR)
        if not self.validate_timestamp_in_req(connection, send_time):
            return
        target_user_info = self.find_user_by_name(target_user_name)
        if target_user_info is not None:
            key_between_client = base64.b64encode(os.urandom(32))
            timestamp_to_expire = time.time() + 1000
            ticket = request_user_info.user_name + SPACE_SEPARATOR + \
                     key_between_client + SPACE_SEPARATOR + \
                     str(timestamp_to_expire)
            ticket_signature = Crypto.sign(self.private_key, ticket)
            target_pubkey = target_user_info.rsa_pub_key
            user_info_msg = UserInfoRes(
                target_user_info.ip,
                target_user_info.port,
                key_between_client,
                ticket,
                ticket_signature,
                Crypto.serialize_pub_key(target_pubkey)
            )
            self.send_encrypted_data_to_client(connection, request_user_info, user_info_msg)
        else:
            msg=dict()
            msg['type'] = MessageStatus.INVALID_RES
            msg['data'] = 'The user <' + target_user_name + '> is offline!'
            connection.sendall(json.dumps(msg))

    def find_user_by_name(self, user_name):
        for user_addr in self.users_loggedin:
            login_user_info = self.users_loggedin[user_addr]
            if login_user_info.user_name == user_name:
                return login_user_info
        return None

    # --------------------------- logout the user ------------------------- #
    def logout_handler(self, request_user_info, client_address, connection, logout_msg):
        n, timestamp = logout_msg.split(LINE_SEPARATOR)
        if not self.validate_timestamp_in_req(connection, timestamp):
            return
        if client_address in self.users_loggedin:
            del self.users_loggedin[client_address]
            logout_res = LogoutRes('OK')
            self.send_encrypted_data_to_client(connection, request_user_info, logout_res)
        else:
            msg = dict()
            msg['type'] = MessageStatus.INVALID_RES
            msg['data'] = 'Trying to logout an offline user!'
            connection.sendall(json.dumps(msg))

    # ------------ Common function using symmetric encryption to send back message to client -------------- #
    @staticmethod
    def send_encrypted_data_to_client(connection, request_user_info, msg, include_timestamp=True):
        iv = base64.b64encode(os.urandom(16))
        if include_timestamp:
            msg.timestamp = time.time()
            msg = pickle.dumps(msg, pickle.HIGHEST_PROTOCOL)
        encrypted_res_message = Crypto.symmetric_encryption(request_user_info.secret_key, iv, msg)
        send_res_msg = dict()
        send_res_msg['type'] = MessageStatus.VALID_RES
        send_res_msg['data'] = Crypto.asymmetric_encryption(request_user_info.rsa_pub_key, iv) + \
                               LINE_SEPARATOR + encrypted_res_message
        connection.sendall(json.dumps(send_res_msg))

    def client_error_handler(self, connection, client_addr):
        if client_addr in self.users_loggedin:
            del self.users_loggedin[client_addr]
        connection.close()

    def server_exit_handler(self):
        while True:
            command = raw_input()
            if command.strip() == 'exit':
                print 'Shutting down the Server..'
                self.sock.close()
                os._exit(0)

    @staticmethod
    def validate_timestamp_in_req(connection, timestamp):
        if not Crypto.validate_timestamp(timestamp):
            msg = dict()
            msg['type'] = MessageStatus.INVALID_RES
            msg['data'] = 'Gap between timestamp is too large, invalid message!'
            connection.sendall(json.dumps(msg))
            return False
        return True

    def generate_challenge(self):
        challenge = Crypto.generate_nonce()
        trunc_challenge = challenge & 0x0000ffffffffffffffffffffffffffff
        challenge_hash = Crypto.generate_hash(str(challenge))
        return challenge, challenge_hash, trunc_challenge

    def run(self):
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            print 'Server started on ' + self.host + ':' + str(self.port) + ' ...'
            threading.Thread(target=self.server_exit_handler, args=()).start()
            while True:
                connection, client_add = self.sock.accept()
                threading.Thread(target=self.client_handler, args=(connection, client_add)).start()
        except socket.error:
            traceback.print_exc()
            print 'Server failed to start'

    # -------------- override default function: will be invoked if inputting invalid command -------------- #
    def default(self, line):
        print 'Enter "exit" to stop the server'


if __name__ == '__main__':
    # Reading the server from config file and starting a socket using that port
    config = ConfigParser.RawConfigParser()
    config.read('configuration/server.cfg')
    port_num = config.getint('info', 'port')
    pri_key = config.get('info', 'private_key')
    user_creds = config.get('info', 'user_creds')
    host_name = Crypto.get_local_ip() # get local ip address by trying to connect to the DNS of google
    server = Server(host_name, port_num,pri_key, user_creds) # Create a server object
    server.run() # Start the socket
