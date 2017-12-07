import base64
import json
import socket
import threading
import csv

import pickle

import Crypto
import os
import Message
import Utils
import time
import traceback
import ConfigParser
from Message import MessageType, AuthStartRes, UserListRes, UserInfoRes, LogoutRes, SEPARATOR, SEPARATOR1, MAX_MSG_SIZE


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
    def __init__(self, host, port, private_key_file, users_info_file):
        self.host = host
        self.port = port
        self.private_key = Crypto.load_private_key(private_key_file)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.all_users = self.read_userInfo(users_info_file)
        self.users_loggedin = dict()

    @staticmethod
    def read_userInfo(users_info_file, delimiter=';', charQuote='|'):
        users_info = dict()
        with open(users_info_file, 'rb') as csv_file:
            rows = csv.reader(csv_file, delimiter=delimiter, quotechar=charQuote)
            for row in rows:
                salt_and_hash = (row[1], row[2])
                username = row[0]
                users_info[username] = salt_and_hash
        return users_info

    def client_handler(self, connection, client_addr):
        try:
            while True:
                msg = connection.recv(MAX_MSG_SIZE)
                if not msg:
                    break
                msg = json.loads(msg)
                msg_type = msg['type']
                data = msg['data']
                # ----------------- handle messages sent from unauthenticated users --------------------#
                # handle authentication init message
                if msg_type == MessageType.INIT and client_addr not in self.users_loggedin:
                    print 'authentication init message received from ', client_addr
                    self.client_handler_for_init(connection, client_addr)
                # handle authentication start message
                elif msg_type == MessageType.AUTH_START and client_addr in self.users_loggedin \
                        and self.users_loggedin[client_addr].state == UserState.INIT:
                    print 'authentication start message received from ', client_addr
                    ver_result, response_msg = self.client_handler_for_auth_start(client_addr, data)
                    msg = dict()
                    msg['data'] = response_msg
                    if not ver_result:
                        msg['type'] = MessageType.RES_FOR_INVALID_REQ
                        connection.sendall(json.dumps(msg))
                        self.client_error_handler(connection, client_addr)
                        break
                    msg['type'] = MessageType.RES_FOR_VALID_REQ
                    connection.sendall(json.dumps(msg))
                # handle authentication end message
                elif msg_type == MessageType.AUTH_END and client_addr in self.users_loggedin \
                        and self.users_loggedin[client_addr].state == UserState.VERIFIED:
                    print 'authentication end message received from ', client_addr
                    auth_result, response_msg = self.client_handler_for_auth_end(client_addr, data)
                    if not auth_result:
                        msg = dict()
                        msg['type'] = MessageType.RES_FOR_INVALID_REQ
                        msg['data'] = response_msg
                        connection.sendall(json.dumps(msg))
                        self.client_error_handler(connection, client_addr)
                        break
                    self.users_loggedin[client_addr].state = UserState.AUTHENTICATED
                    print 'successfully login user: ', self.users_loggedin[client_addr].user_name
                    self.send_encrypted_data_to_client(connection, self.users_loggedin[client_addr], response_msg,
                                                       False)
                # ----------------- handle messages sent from authenticated users --------------------#
                elif client_addr in self.users_loggedin and self.users_loggedin[
                    client_addr].state == UserState.AUTHENTICATED:
                    iv, encrypted_msg = data.split(SEPARATOR)
                    user_info = self.users_loggedin[client_addr]
                    decrypted_msg = Crypto.symmetric_decrypt(user_info.secret_key,
                                                             Crypto.asymmetric_decrypt(self.private_key, iv),
                                                             encrypted_msg)
                    # handle list message
                    if msg_type == MessageType.LIST_USERS:
                        print 'receive list request message from ', client_addr
                        self.client_handler_for_list(user_info, connection, decrypted_msg)
                    # handle get user info message
                    elif msg_type == MessageType.GET_USER_INFO:
                        print 'receive get user info message from ', client_addr
                        self.client_handler_for_loggedUsersInfo(user_info, connection, decrypted_msg)
                    # handle logout message
                    elif msg_type == MessageType.LOGOUT:
                        print 'receive logout message from ', client_addr
                        self.logout_handler(user_info, client_addr, connection, decrypted_msg)
                    else:
                        print 'illegal message type: ', msg_type
        except:
            print 'Error happens when handling client messages, break the connection!'
            self.client_error_handler(connection, client_addr)
        finally:
            print 'Close the connection with ' + str(client_addr)
            connection.close()

    # --------------------------- login related messages ------------------------- #
    def client_handler_for_init(self, connection, client_address):
        challenge, challenge_hash, trunc_challenge = self.generate_challenge()
        connection.sendall(str(trunc_challenge) + SEPARATOR + challenge_hash)
        user_info = UserInfo(str(challenge))
        self.users_loggedin[client_address] = user_info

    def client_handler_for_auth_start(self, client_address, data):
        challenge = Utils.substring_before(data, SEPARATOR)
        auth_start_msg = Crypto.asymmetric_decrypt(self.private_key, Utils.substring_after(data, SEPARATOR))
        deserialized_auth_start_msg = pickle.loads(auth_start_msg)
        # if the challenge solution is wrong, return false directly
        if challenge != self.users_loggedin[client_address].challenge:
            return False, 'Response to the given challenge is incorrect!'
        user_name = deserialized_auth_start_msg.user_name
        # the same user cannot login twice
        user_info = self.find_user_by_name(user_name)
        if user_info is not None and user_info.state == UserState.AUTHENTICATED:
            return False, 'User is already logged in, please logout and retry!'
        # if the provided password is wrong
        password = deserialized_auth_start_msg.password
        if not self.check_password(user_name, password):
            return False, 'The user name or password is wrong!'
        # set user information
        user_obj = self.users_loggedin[client_address]
        user_obj.user_name = deserialized_auth_start_msg.user_name
        user_obj.ip = deserialized_auth_start_msg.ip
        user_obj.port = int(deserialized_auth_start_msg.port)
        user_obj.rsa_pub_key = Crypto.deserialize_pub_key(deserialized_auth_start_msg.rsa_pub_key)
        user_obj.state = UserState.VERIFIED
        # DH key exchange
        user_dh_pub_key = Crypto.deserialize_pub_key(deserialized_auth_start_msg.dh_pub_key)
        dh_pri_key, dh_pub_key = Crypto.generate_dh_key_pair()
        user_obj.secret_key = Crypto.generate_shared_dh_key(dh_pri_key, user_dh_pub_key)
        # compose response message
        c1_nonce = deserialized_auth_start_msg.c1_nonce
        c2_nonce = Utils.generate_nonce(32)
        user_obj.temp_nonce = c2_nonce
        serialized_dh_pub_key = Crypto.serialize_pub_key(dh_pub_key)
        response_obj = AuthStartRes(serialized_dh_pub_key, c1_nonce, c2_nonce)
        response_msg = pickle.dumps(response_obj, pickle.HIGHEST_PROTOCOL)
        encrypted_response_msg = Crypto.asymmetric_encrypt(user_obj.rsa_pub_key, response_msg)
        return True, encrypted_response_msg

    def check_password(self, user_name, password):
        if user_name not in self.all_users:
            return False
        salt, pwd_hash = self.all_users[user_name]
        if Crypto.generate_hash(password, salt) != pwd_hash:
            return False
        return True

    def client_handler_for_auth_end(self, client_address, data):
        user_info = self.users_loggedin[client_address]
        iv, encrypted_c2_nonce = data.split(SEPARATOR)
        received_c2_nonce = Crypto.symmetric_decrypt(user_info.secret_key,
                                                     Crypto.asymmetric_decrypt(self.private_key, iv),
                                                     encrypted_c2_nonce)
        if received_c2_nonce != str(user_info.temp_nonce):
            return False, 'The nonce encrypted with the session key is wrong!'
        auth_end_res_msg = str(long(received_c2_nonce) + 1)
        return True, auth_end_res_msg

    # --------------------------- get all users' names --------------------------- #
    def client_handler_for_list(self, request_user_info, connection, received_list_message):
        list_flag, list_send_time = received_list_message.split(SEPARATOR)
        if self.validate_timestamp_in_req(connection, list_send_time):
            current_user_names = SEPARATOR1.join(user.user_name for client_addr, user in self.users_loggedin.iteritems())
            user_list_res = UserListRes(current_user_names)
            self.send_encrypted_data_to_client(connection, request_user_info, user_list_res)

    # --------------------------- get information of another user ------------------------- #
    def client_handler_for_loggedUsersInfo(self, request_user_info, connection, user_info_msg):
        target_user_name, send_time = user_info_msg.split(SEPARATOR)
        if not self.validate_timestamp_in_req(connection, send_time):
            return
        target_user_info = self.find_user_by_name(target_user_name)
        if target_user_info is not None:
            key_between_client = base64.b64encode(os.urandom(32))
            timestamp_to_expire = time.time() + 1000
            ticket = request_user_info.user_name + SEPARATOR1 + \
                     key_between_client + SEPARATOR1 + \
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
            msg['type'] = MessageType.RES_FOR_INVALID_REQ
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
        n, timestamp = logout_msg.split(SEPARATOR)
        if not self.validate_timestamp_in_req(connection, timestamp):
            return
        if client_address in self.users_loggedin:
            del self.users_loggedin[client_address]
            logout_res = LogoutRes('OK')
            self.send_encrypted_data_to_client(connection, request_user_info, logout_res)
        else:
            msg = dict()
            msg['type'] = MessageType.RES_FOR_INVALID_REQ
            msg['data'] = 'Trying to logout an offline user!'
            connection.sendall(json.dumps(msg))

    # ------------ Common function using symmetric encryption to send back message to client -------------- #
    @staticmethod
    def send_encrypted_data_to_client(connection, request_user_info, msg, include_timestamp=True):
        iv = base64.b64encode(os.urandom(16))
        if include_timestamp:
            msg.timestamp = time.time()
            msg = pickle.dumps(msg, pickle.HIGHEST_PROTOCOL)
        encrypted_res_message = Crypto.symmetric_encrypt(request_user_info.secret_key, iv, msg)
        send_res_msg = dict()
        send_res_msg['type'] = MessageType.RES_FOR_VALID_REQ
        send_res_msg['data'] = Crypto.asymmetric_encrypt(request_user_info.rsa_pub_key, iv) + \
                               SEPARATOR + encrypted_res_message
        connection.sendall(json.dumps(send_res_msg))

    def client_error_handler(self, connection, client_address):
        if client_address in self.users_loggedin:
            del self.users_loggedin[client_address]
        connection.close()

    def exit_handler(self):
        while True:
            command = raw_input()
            if command.strip() == 'exit':
                print 'server shutting down'
                self.sock.close()
                os._exit(0)

    @staticmethod
    def validate_timestamp_in_req(connection, timestamp):
        if not Crypto.validate_timestamp(timestamp):
            msg = dict()
            msg['type'] = MessageType.RES_FOR_INVALID_REQ
            msg['data'] = 'Gap between timestamp is too large, invalid message!'
            connection.sendall(json.dumps(msg))
            return False
        return True

    def generate_challenge(self):
        challenge = Utils.generate_nonce()
        trunc_challenge = challenge & 0x0000ffffffffffffffffffffffffffff
        challenge_hash = Crypto.generate_hash(str(challenge))
        return challenge, challenge_hash, trunc_challenge

    def run(self):
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(1)
            print 'Server started on ' + self.host + ':' + str(self.port) + ' ...'
            threading.Thread(target=self.exit_handler, args=()).start()
            while True:
                connection, client_add = self.sock.accept()
                threading.Thread(target=self.client_handler, args=(connection, client_add)).start()
        except socket.error:
            traceback.print_exc()
            print 'Server failed to start'


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
