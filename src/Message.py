LINE_SEPARATOR = '\n'
SPACE_SEPARATOR = ' '
MAX_BUFFER_SIZE = 65536

MAX_TIMESTAMP_GAP = 10

# --------------------------- Authentication Message Class ------------------------- #
class AuthMsg(object):
    def __init__(self, solved_challenge, user_name,  password, rsa_pub_key, dh_pub_key, ip, port, n1, n2 ):
        self.solved_challenge = solved_challenge
        self.user_name = user_name
        self.password = password
        self.rsa_pub_key = rsa_pub_key
        self.dh_pub_key = dh_pub_key
        self.ip = ip
        self.port = port
        self.n1 = n1
        self.n2 = n2

class UserListRes(object):
    def __init__(self, user_names, timestamp=None):
        self.user_names = user_names
        self.timestamp = timestamp


class UserInfoRes(object):
    def __init__(self, ip, port, sec_key, ticket, ticket_signature, public_key, timestamp=None):
        self.ip = ip
        self.port = port
        self.sec_key = sec_key
        self.ticket = ticket
        self.ticket_signature = ticket_signature
        self.public_key = public_key
        self.timestamp = timestamp


class ConnStartMsg(object):
    def __init__(self, user_name, ip, port, public_key, ticket, ticket_signature, n3, timestamp):
        self.user_name = user_name
        self.ip = ip
        self.port = port
        self.public_key = public_key
        self.ticket = ticket
        self.ticket_signature = ticket_signature
        self.n3 = n3
        self.timestamp = timestamp


class ConnMsg(object):
    def __init__(self, user_name, iv, tag, encrypted_n3, n4, encrypted_n4, timestamp):
        self.user_name = user_name
        self.iv = iv
        self.tag = tag
        self.encrypted_n3 = encrypted_n3
        self.n4 = n4
        self.encrypted_n4 = encrypted_n4
        self.timestamp = timestamp


class TextMsg(object):
    def __init__(self, user_name, iv, tag, encrypted_msg, msg_signature, timestamp):
        self.user_name = user_name
        self.iv = iv
        self.tag = tag
        self.encrypted_msg = encrypted_msg
        self.msg_signature = msg_signature
        self.timestamp = timestamp


class DisconnMsg(object):
    def __init__(self, user_name, timestamp):
        self.user_name = user_name
        self.timestamp = timestamp


class LogoutRes(object):
    def __init__(self, result, timestamp=None):
        self.result = result
        self.timestamp = timestamp

class MessageStatus(object):
    INIT = 'INIT'
    START_AUTH = 'START_AUTH'
    END_AUTH = 'END_AUTH'
    INVALID_RES = 'INVALID_RES'
    VALID_RES = 'VALID_RES'
    LIST = 'LIST'
    TICKET_TO_USER = 'TICKET_TO_USER'
    START_CONN = 'START_CONN'
    END_CONN = 'END_CONN'
    USER_RES = 'USER_RES'
    DISCONNECT = 'DISCONNECT'
    PLAIN_MSG = 'PLAIN_MSG'
    LOGOUT = 'LOGOUT'
