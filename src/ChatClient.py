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
from Message import LINE_SEPARATOR, MessageStatus, AuthStartMsg, MAX_BUFFER_SIZE, SPACE_SEPARATOR, ConnStartMsg, ConnBackMsg, \
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
        self.start_recv_sock()
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
        login_result = False
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
            authentication_complete, self.shared_dh_key, n2 = self.get_server_shared_key(n1, server_auth_response)

            # Step 3: Establish the shared key and finish logging in the user
            if authentication_complete and self.end_authentication(n2):
                login_result = True
        except socket.error:
            print 'Cannot connect to the server in the authentication process, exiting the program!'
            os._exit(0)
        except Exception as e:
            print e
            print 'Unknown error happens when trying to login: ', sys.exc_info()[0], ', please retry!'
        finally:
            if not login_result:
                self.client_sock.close()
            return login_result, user_name

    def login_request(self):
        msg = dict()
        msg['type'] = MessageStatus.INIT
        msg['data'] = ''
        init_msg = json.dumps(msg)
        self.client_sock.sendall(init_msg)
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
        send_msg = AuthStartMsg(
            user_name,
            password,
            Crypto.serialize_pub_key(self.rsa_pub_key),
            Crypto.serialize_pub_key(self.dh_pub_key),
            self.client_ip,
            self.client_port,
            n1
        )
        msg_str = pickle.dumps(send_msg, pickle.HIGHEST_PROTOCOL)
        encrypted_msg = Crypto.asymmetric_encryption(self.server_pub_key, msg_str)
        full_msg = solved_challenge + LINE_SEPARATOR + encrypted_msg
        msg = dict()
        msg['type'] = MessageStatus.START_AUTH
        msg['data'] = full_msg
        auth_start_msg = json.dumps(msg)
        self.client_sock.sendall(auth_start_msg)
        server_auth_response = self.client_sock.recv(MAX_BUFFER_SIZE)
        return n1, server_auth_response

    def get_server_shared_key(self, expected_n1, server_auth_response):
        msg = json.loads(server_auth_response)
        msg_type = msg['type']
        data = msg['data']
        if msg_type == MessageStatus.INVALID_RES:
            #print data
            return False, None, None
        decrypted_auth_start_response = Crypto.asymmetric_decryption(self.rsa_pri_key, data)
        res_obj = pickle.loads(decrypted_auth_start_response)
        server_dh_key, n1, n2 = res_obj.dh_pub_key, res_obj.n1, res_obj.n2
        if str(expected_n1) != str(n1):
            return False, None, None
        shared_dh_key = Crypto.generate_shared_dh_key(self.dh_pri_key, Crypto.deserialize_pub_key(server_dh_key))
        return True, shared_dh_key, str(n2)

    def end_authentication(self, n2):
        iv = base64.b64encode(os.urandom(16))
        encrypted_n2 = Crypto.symmetric_encryption(self.shared_dh_key, iv, n2)
        msg = dict()
        msg['type'] = MessageStatus.END_AUTH
        msg['data'] = Crypto.asymmetric_encryption(self.server_pub_key, iv) + LINE_SEPARATOR + encrypted_n2
        auth_end_msg = json.dumps(msg)
        self.client_sock.sendall(auth_end_msg)
        validate_result, decrypted_nonce_response = self._recv_sym_encrypted_msg_from_server(False)
        if validate_result and long(decrypted_nonce_response) == long(n2) + 1:
            return True
        else:
            return False

    # --------------------------- list online users ------------------------- #
    def do_list(self, arg):
        try:
            self._send_sym_encrypted_msg_to_server(MessageStatus.LIST, 'list')
            validate_result, list_response = self._recv_sym_encrypted_msg_from_server()
            if validate_result:
                print MSG_PROMPT + 'Online users: ' + ', '.join(list_response.user_names.split(SPACE_SEPARATOR))
                # set the client information in self.online_list
                parsed_list_response = list_response.user_names.split(SPACE_SEPARATOR)
                for user in parsed_list_response:
                    if user != self.user_name and user not in self.online_list:
                        self.online_list[user] = UserInfo()
        except (socket.error, ValueError) as e:
            self._re_login()
        except:
            print 'Unknown error while trying to get online user list from the server!'

    # --------------------------- send message to another user ------------------------- #
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
                receiver_info = self.online_list[receiver_name]
                # if we don't know the receiver's user information
                if not receiver_info.info_known:
                    self._get_user_info(receiver_name)
                # if we haven't connected to this user
                if receiver_info.info_known and not receiver_info.connected:
                    self._connect_to_user(receiver_info)
                    # wait 1 seconds before successfully connected
                    time.sleep(1)
                # if we have already connected to this user, send message to the user
                if receiver_info.connected:
                    print 'Sent message to the user <' + receiver_name + '>'
                    self._send_text_msg(msg, receiver_info)
                # otherwise we cannot send message to the user
                else:
                    print 'Cannot send message to the user because it is not connected.'
        except (socket.error, ValueError) as e:
            self._re_login()
        except:
            print 'Unknown error happens when trying to send message to another user!'

    # --------------------------- get user information from the server ------------------------- #
    def _get_user_info(self, user_name):
        self._send_sym_encrypted_msg_to_server(MessageStatus.TICKET_TO_USER, user_name)
        validate_result, user_info_obj = self._recv_sym_encrypted_msg_from_server()
        if validate_result:
            # print target_address
            user_info = self.online_list[user_name]
            user_info.address = (user_info_obj.ip, user_info_obj.port)
            user_info.sec_key = user_info_obj.sec_key
            user_info.pub_key = Crypto.deserialize_pub_key(user_info_obj.pub_key)
            user_info.ticket = user_info_obj.ticket
            user_info.ticket_signature = user_info_obj.ticket_signature
            user_info.info_known = True

    # --------------------------- build connection with the user ------------------------- #
    def _connect_to_user(self, target_user_info):
        # start authentication process
        target_user_info.n3 = Crypto.generate_nonce()
        msg = ConnStartMsg(
            self.user_name,
            self.client_ip,
            self.client_port,
            Crypto.serialize_pub_key(self.rsa_pub_key),
            target_user_info.ticket,
            target_user_info.ticket_signature,
            target_user_info.n3,
            time.time()
        )
        self._send_encrypted_msg_to_user(target_user_info, MessageStatus.START_CONN, msg)

    # --------------------------- send the final message to the target user ------------------------- #
    def _send_text_msg(self, msg, receiver_info):
        iv = base64.b64encode(os.urandom(16))
        sec_key = receiver_info.sec_key
        text_msg = TextMsg(
            self.user_name,
            Crypto.asymmetric_encryption(receiver_info.pub_key, iv),
            Crypto.symmetric_encryption(sec_key, iv, msg),
            Crypto.sign(self.rsa_pri_key, msg),
            time.time()
        )
        self._send_encrypted_msg_to_user(receiver_info, MessageStatus.PLAIN_MSG, text_msg)

    # --------------------------- start a server socket to receive messages from other users ------------------------- #
    def start_recv_sock(self):
        try:
            print 'Start recv socket on ' + self.client_ip + ':' + str(self.client_port)
            self.recv_sock.bind((self.client_ip, self.client_port))
            threading.Thread(target=self.listen_for_message).start()
        except socket.error:
            print 'Failed to start the socket for receiving messages'

    def listen_for_message(self):
        while True:
            msg, addr = self.recv_sock.recvfrom(MAX_BUFFER_SIZE)
            if not msg:
                break
            print 'Receive message from ', addr, ':\n', msg
            msg = json.loads(msg)
            msg_type = msg['type']
            data = msg['data']
            decrypted_data = Crypto.asymmetric_decryption(self.rsa_pri_key, data)
            msg_obj = pickle.loads(decrypted_data)
            # if the message's timestamp is invalid
            if not Crypto.validate_timestamp(msg_obj.timestamp):
                print 'Timestamp of the message from another user is invalid, drop the message!'
                continue
            if msg_type == MessageStatus.START_CONN:
                self._handle_conn_start(msg_obj)
            elif msg_type == MessageStatus.END_CONN:
                self._handle_conn_back(msg_obj)
            elif msg_type == MessageStatus.USER_RES:
                self._handle_conn_end(msg_obj)
            elif msg_type == MessageStatus.DISCONNECT:
                self._handle_disconn_msg(msg_obj)
            elif msg_type == MessageStatus.PLAIN_MSG:
                self._handle_text_msg(msg_obj)

    def _handle_conn_start(self, conn_start_msg):
        ticket = conn_start_msg.ticket
        ticket_signature = conn_start_msg.ticket_signature
        if not Crypto.verify_signature(self.server_pub_key, ticket, ticket_signature):
            return
        src_user_name, sec_session_key, timestamp_to_expire = ticket.split(SPACE_SEPARATOR)
        if src_user_name != conn_start_msg.user_name or float(timestamp_to_expire) < time.time():
            return
        src_user_info = UserInfo()
        src_user_info.address = (conn_start_msg.ip, conn_start_msg.port)
        src_user_info.pub_key = Crypto.deserialize_pub_key(conn_start_msg.pub_key)
        src_user_info.sec_key = sec_session_key
        src_user_info.info_known = True
        self.online_list[conn_start_msg.user_name] = src_user_info
        # send connection back message to the initiator
        n3 = conn_start_msg.n3
        src_user_info.n4 = Crypto.generate_nonce()
        iv = base64.b64encode(os.urandom(16))
        conn_back_msg = ConnBackMsg(
            self.user_name,
            iv,
            Crypto.symmetric_encryption(src_user_info.sec_key, iv, str(n3)),
            src_user_info.n4,
            time.time()
        )
        self._send_encrypted_msg_to_user(src_user_info, MessageStatus.END_CONN, conn_back_msg)

    def _handle_conn_back(self, conn_back_msg):
        user_info = self.online_list[conn_back_msg.user_name]
        decrypted_n3 = Crypto.symmetric_decryption(user_info.sec_key,
                                                      conn_back_msg.iv,
                                                      conn_back_msg.encrypted_n3)
        if str(decrypted_n3) == str(user_info.n3):
            # print 'Successfully connected to the user <' + conn_back_msg.user_name + '>'
            user_info.connected = True
            iv = base64.b64encode(os.urandom(16))
            conn_end_msg = ConnEndMsg(
                self.user_name,
                iv,
                Crypto.symmetric_encryption(user_info.sec_key, iv, str(conn_back_msg.n4)),
                time.time()
            )
            self._send_encrypted_msg_to_user(user_info, MessageStatus.USER_RES, conn_end_msg)

    def _handle_conn_end(self, conn_end_msg):
        user_info = self.online_list[conn_end_msg.user_name]
        decrypted_n4 = Crypto.symmetric_decryption(user_info.sec_key, conn_end_msg.iv,
                                                      conn_end_msg.encrypted_n4)
        if str(user_info.n4) == str(decrypted_n4):
            user_info.connected = True

    def _handle_text_msg(self, text_msg):
        user_name = text_msg.user_name
        if user_name in self.online_list and self.online_list[user_name].connected:
            user_info = self.online_list[user_name]
            iv = Crypto.asymmetric_decryption(self.rsa_pri_key, text_msg.iv)
            encrypted_msg = text_msg.encrypted_msg
            decrypted_msg = Crypto.symmetric_decryption(user_info.sec_key, iv, encrypted_msg)
            msg_signature = text_msg.msg_signature
            if Crypto.verify_signature(user_info.pub_key, decrypted_msg, msg_signature):
                print '\n' + MSG_PROMPT + user_name + " has sent you: " + decrypted_msg
                print self.user_name + CMD_PROMPT,

    def _handle_disconn_msg(self, disconn_msg):
        user_name = disconn_msg.user_name
        if user_name in self.online_list:
            del self.online_list[user_name]

    # --------------------------- logout the user and exit the program ------------------------- #
    def do_logout(self, arg):
        try:
            if self._logout_from_server():
                print '<' + self.user_name + '> successfully logged out.'
                self._disconnect_all_users()
                self.client_sock.close()
                self.recv_sock.close()
                os._exit(0)
        except:
            print 'Error happens when trying to exit the client!'
            os._exit(0)

    def _logout_from_server(self):
        self._send_sym_encrypted_msg_to_server(MessageStatus.LOGOUT, '')
        result, msg = self._recv_sym_encrypted_msg_from_server()
        return result

    def _disconnect_all_users(self):
        for user_name, user_info in self.online_list.iteritems():
            if user_info.connected:
                print 'Disconnecting the user <' + user_name + '>'
                disconn_msg = DisconnMsg(self.user_name, time.time())
                self._send_encrypted_msg_to_user(user_info, MessageStatus.DISCONNECT, disconn_msg)

    # ------------------------ try to re-login if server broken down or reset ----------------------- #
    def _re_login(self):
        print 'Server broken down or reset, please try to re-login!'
        self.client_sock.close()
        self.user_name = None
        self.rsa_pri_key, self.rsa_pub_key = Crypto.generate_rsa_key_pair()
        self.dh_pri_key, self.dh_pub_key = Crypto.generate_dh_key_pair()
        self.shared_dh_key = None
        self.login()

    # --------------------------- common functions for message exchange ------------------------- #
    def _send_sym_encrypted_msg_to_server(self, message_type, msg):
        send_time = time.time()
        iv = base64.b64encode(os.urandom(16))
        plain_msg = msg + LINE_SEPARATOR + str(send_time)
        encrypted_msg = Crypto.symmetric_encryption(self.shared_dh_key, iv, plain_msg)
        msg = dict()
        msg['type'] = message_type 
        msg['data'] = Crypto.asymmetric_encryption(self.server_pub_key, iv) + LINE_SEPARATOR + encrypted_msg
        final_msg = json.dumps(msg)
        self.client_sock.sendall(final_msg)

    def _recv_sym_encrypted_msg_from_server(self, validate_timestamp=True):
        encrypted_server_response = self.client_sock.recv(MAX_BUFFER_SIZE)
        msg = json.loads(encrypted_server_response)
        msg_type = msg['type']
        data = msg['data']
        if msg_type == MessageStatus.INVALID_RES:
            #print data
            return False, data
        else:
            iv, encrypted_response_without_iv = data.split(LINE_SEPARATOR)
            decrypted_response = Crypto.symmetric_decryption(self.shared_dh_key,
                                                          Crypto.asymmetric_decryption(self.rsa_pri_key, iv),
                                                          encrypted_response_without_iv)
            if validate_timestamp:
                decrypted_response = pickle.loads(decrypted_response)
                if not Crypto.validate_timestamp(decrypted_response.timestamp):
                    return False, None
            return True, decrypted_response

    def _send_encrypted_msg_to_user(self, target_user_info, message_type, msg_obj):
        encrypted_msg = Crypto.asymmetric_encryption(target_user_info.pub_key,
                                                  pickle.dumps(msg_obj, pickle.HIGHEST_PROTOCOL))
        msg = dict()
        msg['type'] = message_type 
        msg['data'] = encrypted_msg
        msg = json.dumps(msg)
        self.send_sock.sendto(msg, target_user_info.address)

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

    # -------------- override default function: will be invoked if inputting invalid command -------------- #
    def default(self, line):
        print '<------ Commands supported ------>'
        print '1. list: list all online user names'
        print '2. send <username> <message>: send message to another online user'
        print '3. logout: logout current user from the server'
        print '<-------------------------------------------------------->'


if __name__ == '__main__':
    config = ConfigParser.RawConfigParser()
    config.read('configuration/client.cfg')
    # server_ip = config.get('server_info', 'ip')
    server_ip = Crypto.get_local_ip()
    server_port = config.getint('server_info', 'port')
    server_pub_key = config.get('server_info', 'pub_key')

    # initialize the client
    client = Client(server_ip, server_port, server_pub_key)
    # connect the client to the chat server
    client.run()
