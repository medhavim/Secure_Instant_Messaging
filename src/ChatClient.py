import base64
import cmd
import ConfigParser
import Crypto
import getpass
import json
import os
import pickle
import socket
import sys
import threading
import time
from Message import LINE_SEPARATOR, MessageStatus, AuthMsg, MAX_BUFFER_SIZE, SPACE_SEPARATOR, ConnStartMsg, ConnBackMsg, \
    ConnEndMsg, TextMsg, DisconnMsg

MAX_LOGIN_ATTEMPTS = 3
CMD_PROMPT = '>> '
MSG_PROMPT = '<< '


class UserInfo:
    def __init__(self):
        self.address = None
        self.sec_key = None
        self.pub_key = None
        self.ticket = None
        self.ticket_signature = None
        self.info_known = False
        self.n3 = None
        self.n4 = None
        self.connected = False


class Client(cmd.Cmd):
    def __init__(self, ip, port, pub_key_file):
        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.client_sock = None
        # user name for this chat client
        self.user_name = None
        # chat server ip, port and public key
        self.server_ip = ip
        self.server_port = port
        self.server_pub_key = Crypto.load_public_key(pub_key_file)
        # generate rsa key pair
        self.rsa_pri_key, self.rsa_pub_key = Crypto.generate_rsa_key_pair()
        # generate dh key pair
        self.dh_pri_key, self.dh_pub_key = Crypto.generate_dh_key_pair()
        # shared dh key
        self.shared_dh_key = None
        # chat client ip and port, used to receive messages
        self.client_ip = Crypto.get_local_ip()
        self.client_port = Crypto.get_free_port()
        # online-users known to the chatclient
        self.online_list = dict()
        # start socket for receiving messages
        self.run_receive_socket()
        # start commandline interactive mode
        cmd.Cmd.__init__(self)

    # --------------------------- login to the server ------------------------- #
    def run(self):
        login_attempts = 0
        loggedIn = False
        while login_attempts < MAX_LOGIN_ATTEMPTS and not loggedIn:
            loggedIn, user_name = self.login()
            login_attempts += 1
            if loggedIn:
                self.user_name = user_name
                client.prompt = self.user_name + CMD_PROMPT
                client.cmdloop('<' + user_name + '> successfully logged in')
        if not loggedIn:
            print 'Exceeded the maximum login attempts, exiting the program.'
            print 'Please try again later!'
            self.recv_sock.close()
            os._exit(0)

    def login(self):
        user_name = raw_input('Enter your username: ')
        password = getpass.getpass('Enter your password: ')
        log_result = False
        self.user_name = user_name
        try:
            self.client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_sock.connect((self.server_ip, self.server_port))

            # Step 1: Send the request to login to the server5
            challenge = self.login_request()
            solved_challenge = self.solve_server_challenge(challenge)

            # Step 2: start the authentication with the server
            # Send the solved challenge along with A's identity to authenticate to the server
            n1, server_auth_response = self.start_authentication(solved_challenge, user_name, password)
            isAuthenticationComplete, self.shared_dh_key, n2 = self.get_server_shared_key(n1, server_auth_response)

            # Step 3: Establish the shared key and finish logging in the user
            if isAuthenticationComplete and self.end_authentication(n2):
                log_result = True
        except socket.error:
            print 'Cannot connect to the server to authenticate, exiting the program!'
            os._exit(0)
        except Exception as e:
            print e
            print 'Unknown error happens when trying to login: ', sys.exc_info()[0], ', please retry!'
        finally:
            if not log_result:
                self.client_sock.close()
            return log_result, user_name

    def login_request(self):
        msg = dict()
        msg['type'] = MessageStatus.INIT
        msg['data'] = ''
        self.client_sock.sendall(json.dumps(msg))
        challenge = self.client_sock.recv(MAX_BUFFER_SIZE)
        return challenge

    def solve_server_challenge(self, challenge):
        index = challenge.find(LINE_SEPARATOR)
        if index != -1:
            trunc_challenge = challenge[0:index].strip()
            challenge_hash = challenge[index:].strip()
        else:
            trunc_challenge = ''
            challenge_hash = ''

        solved_challenge = self.solve_challenge(trunc_challenge, challenge_hash)
        return solved_challenge

    def start_authentication(self, solved_challenge, user_name, password):
        n1 = Crypto.generate_nonce()
        send_msg = AuthMsg(
            solved_challenge,
            user_name,
            password,
            Crypto.serialize_pub_key(self.rsa_pub_key),
            Crypto.serialize_pub_key(self.dh_pub_key),
            self.client_ip,
            self.client_port,
            n1,
            ''
        )
        msg_str = pickle.dumps(send_msg, pickle.HIGHEST_PROTOCOL)
        encrypted_msg = Crypto.asymmetric_encryption(self.server_pub_key, msg_str)
        msg = dict()
        msg['type'] = MessageStatus.START_AUTH
        msg['data'] = encrypted_msg
        auth_start_msg = json.dumps(msg)
        self.client_sock.sendall(auth_start_msg)
        server_auth_response = self.client_sock.recv(MAX_BUFFER_SIZE)
        return n1, server_auth_response

    def get_server_shared_key(self, expected_n1, server_auth_response):
        msg = json.loads(server_auth_response)
        msg_type = msg['type']
        if msg_type == MessageStatus.INVALID_RES:
            return False, None, None
        decrypted_server_auth_response = pickle.loads(Crypto.asymmetric_decryption(self.rsa_pri_key, msg['data']))
        server_dh_key, n1, n2 = decrypted_server_auth_response.dh_pub_key, \
                                decrypted_server_auth_response.n1, decrypted_server_auth_response.n2
        if str(expected_n1) != str(n1):
            return False, None, None
        shared_dh_key = Crypto.generate_shared_dh_key(self.dh_pri_key, Crypto.deserialize_pub_key(server_dh_key))
        return True, shared_dh_key, str(n2)

    def end_authentication(self, n2):
        iv = base64.b64encode(os.urandom(16))
        encrypted_n2, tag = Crypto.symmetric_encryption(self.shared_dh_key, iv, n2)
        msg = dict()
        msg['type'] = MessageStatus.END_AUTH
        msg['data'] = Crypto.asymmetric_encryption(self.server_pub_key, iv) + LINE_SEPARATOR+\
                      Crypto.asymmetric_encryption(self.server_pub_key, tag)+ LINE_SEPARATOR + encrypted_n2
        self.client_sock.sendall(json.dumps(msg))
        isResultValid, decrypted_nonce_res = self.receive_encrypted_data_from_server(False)
        if isResultValid and long(decrypted_nonce_res) == long(n2) + 1:
            return True
        else:
            return False


    # --------------------------- send message to server to get other client info ------------------------- #
    def get_user_details(self, user_name):
        self.send_encrypted_data_to_server(MessageStatus.TICKET_TO_USER, user_name)
        isResultValid, user_info = self.receive_encrypted_data_from_server()
        if isResultValid:
            user_dict = self.online_list[user_name]
            user_dict.address = (user_info.ip, user_info.port)
            user_dict.sec_key = user_info.sec_key
            user_dict.pub_key = Crypto.deserialize_pub_key(user_info.pub_key)
            user_dict.ticket = user_info.ticket
            user_dict.ticket_signature = user_info.ticket_signature
            user_dict.info_known = True

    # --------------------------- establish connection with another user ------------------------- #
    def connect_to_client(self, target_client_info):
        # start authentication process
        target_client_info.n3 = Crypto.generate_nonce()
        msg = ConnStartMsg(
            self.user_name,
            self.client_ip,
            self.client_port,
            Crypto.serialize_pub_key(self.rsa_pub_key),
            target_client_info.ticket,
            target_client_info.ticket_signature,
            target_client_info.n3,
            time.time()
        )
        self.send_encrypted_data_to_client(target_client_info, MessageStatus.START_CONN, msg)

    # --------------------------- send message to the another client user ------------------------- #
    def create_msg(self, msg, target_info):
        iv = base64.b64encode(os.urandom(16))
        sec_key = target_info.sec_key
        msg = TextMsg(
            self.user_name,
            Crypto.asymmetric_encryption(target_info.pub_key, iv),
            Crypto.asymmetric_encryption(target_info.pub_key, Crypto.symmetric_encryption(sec_key, iv, msg)[1]),
            Crypto.symmetric_encryption(sec_key, iv, msg)[0],
            Crypto.sign(self.rsa_pri_key, msg),
            time.time()
        )
        self.send_encrypted_data_to_client(target_info, MessageStatus.PLAIN_MSG, msg)

    def run_receive_socket(self):
        try:
            print 'Start client socket on ' + self.client_ip + ':' + str(self.client_port)
            self.recv_sock.bind((self.client_ip, self.client_port))
            threading.Thread(target=self.start_listening).start()
        except socket.error:
            print 'Failed to start the socket for receiving messages'

    def start_listening(self):
        while True:
            msg, address = self.recv_sock.recvfrom(MAX_BUFFER_SIZE)
            if not msg:
                break
            msg = json.loads(msg)
            msg_type = msg['type']
            msg_from_client = pickle.loads(Crypto.asymmetric_decryption(self.rsa_pri_key, msg['data']))
            if not Crypto.validate_timestamp(msg_from_client.timestamp):
                print 'Timestamp of the message from another user is invalid'
                continue
            if msg_type == MessageStatus.START_CONN:
                self.start_connection(msg_from_client)
            elif msg_type == MessageStatus.END_CONN:
                self.response_to_connection(msg_from_client)
            elif msg_type == MessageStatus.USER_RES:
                self.end_connection(msg_from_client)
            elif msg_type == MessageStatus.DISCONNECT:
                self.disconnect_client(msg_from_client)
            elif msg_type == MessageStatus.PLAIN_MSG:
                self.decrypt_msg_from_client(msg_from_client)

    def start_connection(self, msg_received):
        ticket = msg_received.ticket
        ticket_signature = msg_received.ticket_signature
        if not Crypto.verify_signature(self.server_pub_key, ticket, ticket_signature):
            return
        user_name_in_ticket, session_key_in_ticket, timestamp_to_expire = ticket.split(SPACE_SEPARATOR)
        if user_name_in_ticket != msg_received.user_name or float(timestamp_to_expire) < time.time():
            return
        received_from_user = UserInfo()
        received_from_user.address = (msg_received.ip, msg_received.port)
        received_from_user.pub_key = Crypto.deserialize_pub_key(msg_received.pub_key)
        received_from_user.sec_key = session_key_in_ticket
        received_from_user.info_known = True
        self.online_list[msg_received.user_name] = received_from_user
        # send connection back message to the initiator
        n3 = msg_received.n3
        received_from_user.n4 = Crypto.generate_nonce()
        iv = base64.b64encode(os.urandom(16))
        response_msg = ConnBackMsg(
            self.user_name,
            iv,
            Crypto.symmetric_encryption(received_from_user.sec_key, iv, str(n3))[1],
            Crypto.symmetric_encryption(received_from_user.sec_key, iv, str(n3))[0],
            received_from_user.n4,
            time.time()
        )
        self.send_encrypted_data_to_client(received_from_user, MessageStatus.END_CONN, response_msg)

    def response_to_connection(self, msg_received):
        user_dict = self.online_list[msg_received.user_name]
        decrypted_n3 = Crypto.symmetric_decryption(user_dict.sec_key,
                                                   msg_received.iv,
                                                   msg_received.tag,
                                                   msg_received.encrypted_n3)
        if str(decrypted_n3) == str(user_dict.n3):
            user_dict.connected = True
            iv = base64.b64encode(os.urandom(16))
            response_to_client = ConnEndMsg(
                self.user_name,
                iv,
                Crypto.symmetric_encryption(user_dict.sec_key, iv, str(msg_received.n4))[1],
                Crypto.symmetric_encryption(user_dict.sec_key, iv, str(msg_received.n4))[0],
                time.time()
            )
            self.send_encrypted_data_to_client(user_dict, MessageStatus.USER_RES, response_to_client)

    def end_connection(self, conn_end_msg):
        user_info = self.online_list[conn_end_msg.user_name]
        decrypted_n4 = Crypto.symmetric_decryption(user_info.sec_key, conn_end_msg.iv, conn_end_msg.tag,
                                                      conn_end_msg.encrypted_n4)
        if str(user_info.n4) == str(decrypted_n4):
            user_info.connected = True

    def decrypt_msg_from_client(self, msg):
        user_name = msg.user_name
        if user_name in self.online_list and self.online_list[user_name].connected:
            user_dict = self.online_list[user_name]
            iv = Crypto.asymmetric_decryption(self.rsa_pri_key, msg.iv)
            tag = Crypto.asymmetric_decryption(self.rsa_pri_key, msg.tag)
            decrypted_msg = Crypto.symmetric_decryption(user_dict.sec_key, iv, tag, msg.encrypted_msg)
            if Crypto.verify_signature(user_dict.pub_key, decrypted_msg, msg.msg_signature):
                print '\n' + MSG_PROMPT + user_name + " has sent you: " + decrypted_msg
                print self.user_name + CMD_PROMPT,

    def disconnect_client(self, disconnect_msg):
        user_name = disconnect_msg.user_name
        if user_name in self.online_list:
            del self.online_list[user_name]

    def server_logout(self):
        self.send_encrypted_data_to_server(MessageStatus.LOGOUT, '')
        isValid, msg = self.receive_encrypted_data_from_server()
        return isValid

    def disconnect_other_clients(self):
        for user_name, user_dict in self.online_list.iteritems():
            if user_dict.connected:
                print 'Disconnecting the user <' + user_name + '>'
                disconnect_msg = DisconnMsg(self.user_name, time.time())
                self.send_encrypted_data_to_client(user_dict, MessageStatus.DISCONNECT, disconnect_msg)

    # ------------------------ try to re-login if something went wrong in server ----------------------- #
    def retry_login(self):
        print 'Something went wrong with server, please try to login again!'
        self.client_sock.close()
        self.user_name = None
        self.rsa_pri_key, self.rsa_pub_key = Crypto.generate_rsa_key_pair()
        self.dh_pri_key, self.dh_pub_key = Crypto.generate_dh_key_pair()
        self.shared_dh_key = None
        self.run()

    # --------------------------- function to send/receive data from server/client ------------------------- #
    def send_encrypted_data_to_server(self, message_type, data):
        send_time = time.time()
        iv = base64.b64encode(os.urandom(16))
        plain_msg = data + LINE_SEPARATOR + str(send_time)
        encrypted_msg, tag = Crypto.symmetric_encryption(self.shared_dh_key, iv, plain_msg)
        msg = dict()
        msg['type'] = message_type
        msg['data'] = Crypto.asymmetric_encryption(self.server_pub_key, iv) + LINE_SEPARATOR+\
                      Crypto.asymmetric_encryption(self.server_pub_key, tag)+ LINE_SEPARATOR + encrypted_msg
        self.client_sock.sendall(json.dumps(msg))

    def receive_encrypted_data_from_server(self, validate_timestamp=True):
        encrypted_response = self.client_sock.recv(MAX_BUFFER_SIZE)
        msg = json.loads(encrypted_response)
        msg_type = msg['type']
        data = msg['data']
        if msg_type == MessageStatus.INVALID_RES:
            return False, data
        else:
            iv, tag, encrypted_response_without_iv = data.split(LINE_SEPARATOR)
            response_from_server = Crypto.symmetric_decryption(self.shared_dh_key,
                                                          Crypto.asymmetric_decryption(self.rsa_pri_key, iv),
                                                          Crypto.asymmetric_decryption(self.rsa_pri_key, tag),
                                                          encrypted_response_without_iv)
            if validate_timestamp:
                response_from_server = pickle.loads(response_from_server)
                if not Crypto.validate_timestamp(response_from_server.timestamp):
                    return False, None
            return True, response_from_server

    def send_encrypted_data_to_client(self, target_client, msg_type, msg_obj):
        response_to_server = Crypto.asymmetric_encryption(target_client.pub_key,
                                                     pickle.dumps(msg_obj, pickle.HIGHEST_PROTOCOL))
        msg = dict()
        msg['type'] = msg_type
        msg['data'] = response_to_server
        self.send_sock.sendto(json.dumps(msg), target_client.address)

    @staticmethod
    def solve_challenge(trunc_challenge, challenge_hash):
        trunc_challenge = long(trunc_challenge)
        guessed_challenge = trunc_challenge
        n = 0
        while len(str(guessed_challenge)) <= 40:
            guessed_challenge = str(trunc_challenge + (n << 112))
            if Crypto.generate_hash(guessed_challenge) == challenge_hash:
                return guessed_challenge
            n += 1

        # --------------------------- show online clients ------------------------- #
    def do_list(self, arg):
        try:
            self.send_encrypted_data_to_server(MessageStatus.LIST, 'list')
            isValid, response_of_list = self.receive_encrypted_data_from_server()
            if isValid:
                print MSG_PROMPT + 'Online users: ' + ', '.join(response_of_list.user_names.split(SPACE_SEPARATOR))
                # set the client information in self.online_list
                parsed_list_response = response_of_list.user_names.split(SPACE_SEPARATOR)
                for user in parsed_list_response:
                    if user != self.user_name and user not in self.online_list:
                        self.online_list[user] = UserInfo()
        except (socket.error, ValueError) as e:
            self.retry_login()
        except:
            print 'Unknown error while trying to get online user list from the server!'

        # --------------------------- send message to other clients ------------------------- #
    def do_send(self, arg):
        try:
            index = arg.find(SPACE_SEPARATOR)
            if index != -1:
                receiver_name = arg[0:index].strip()
                msg = arg[index:].strip()
            else:
                receiver_name = ''
                msg = ''
            if receiver_name == self.user_name:
                print 'Cannot send message to yourself!'
            elif receiver_name not in self.online_list:
                print 'User not in client list! Try using list command to update the client list.'
            else:
                destination_info = self.online_list[receiver_name]
                # if we don't know the receiver's user information
                if not destination_info.info_known:
                    self.get_user_details(receiver_name)
                # if we haven't connected to this user
                if destination_info.info_known and not destination_info.connected:
                    self.connect_to_client(destination_info)
                    # wait 1 seconds before successfully connected
                    time.sleep(1)
                # if we have already connected to this user, send message to the user
                if destination_info.connected:
                    print 'Sending message to the user <' + receiver_name + '>'
                    self.create_msg(msg, destination_info)
                # otherwise we cannot send message to the user
                else:
                    print 'Cannot send message to the client because it is not online.'
        except (socket.error, ValueError) as e:
            self.retry_login()
        except:
            print 'Unknown error happened when trying to send message to another user!'

        # --------------------------- logout the user and exit the program ------------------------- #
    def do_logout(self, arg):
        try:
            if self.server_logout():
                print '<' + self.user_name + '> successfully logged out.'
                self.disconnect_other_clients()
                self.client_sock.close()
                self.recv_sock.close()
                os._exit(0)
        except:
            print 'Error happened when trying to exit the client!'
            os._exit(0)

    def do_exit(self, arg):
        try:
            if self.server_logout():
                print '<' + self.user_name + '> successfully logged out.'
                self.disconnect_other_clients()
                self.client_sock.close()
                self.recv_sock.close()
                os._exit(0)
        except:
            print 'Error happened when trying to exit the client!'
            os._exit(0)

    # -------------- override default function------------------------------------------- #
    def default(self, line):
        print '<----------------------- Commands supported ----------------------->'
        print '1. list: List all online users'
        print '2. send <username> <message>: Send message to another online user'
        print '3. logout / exit: Exit / Logout the current user from the server'



if __name__ == '__main__':
    config = ConfigParser.RawConfigParser()
    config.read('configuration/client.cfg')
    # server_ip = config.get('server_info', 'ip')
    server_ip = Crypto.get_local_ip()
    server_port = config.getint('server_info', 'port')
    server_public_key = config.get('server_info', 'public_key')

    # initialize the client
    client = Client(server_ip, server_port, server_public_key)
    # connect the client to the chat server
    client.run()
