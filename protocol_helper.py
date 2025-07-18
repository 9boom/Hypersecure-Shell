import heapq
import threading
import time
from packets import as_server, as_client

class ServerManager:
    def __init__ (self, logger):
        self.logger = logger
        self.sock = None

    def use_sock(self,sock):
        self.sock = sock

    def wait_recv_utf8(self): # wait recv
        data = self.wait_recv()
        if data is not None:
           return data.decode('utf-8')

    def wait_recv(self):
           data = self.sock.recv(1024)
           if not data:
              return
           return data

    def shoot(self, data: bytes):
             try:
                self.sock.sendall(data)
             except Exception as e:
                self.logger.error(f"During sent [ERROR: {e}]")

    def try_handshake(self):
        self.shoot(as_server.HANDSHAKE)
        data=self.wait_recv_utf8()
        if data.startswith(as_client.HANDSHAKE.decode()):
           self.shoot(as_server.CONNECTION_APPROVED)
           return True
        return False
    def kick(self,reason):
        self.shoot(as_server.KICK+reason.encode()+b'\n')
    def req_passwd(self, enable = True):
        if enable:
           self.shoot(as_server.PASSWORD_REQUEST)
           user_passwd = self.wait_recv_utf8()
           user_passwd = user_passwd.strip()
           if user_passwd == "680086":
              self.shoot(as_server.AUTH_PASSED)
              return True
           elif not user_passwd == "680086":
              self.shoot(as_server.AUTH_FAILED)
              return False
        elif not enable:
           self.shoot(as_server.AUTH_PASSED)
           return True
    def goodbye(self):
        self.shoot(as_server.BYE)
    def no_kicks(self):
        self.shoot(as_server.NO_KICKS)

class ClientManager:
    def __init__ (self, logger, sock):
        self.logger = logger
        self.sock = sock

    def wait_recv_utf8(self): # wait recv
        data = self.wait_recv()
        if data is not None:
           return data.decode('utf-8')

    def wait_recv(self):
           data = self.sock.recv(1024)
           if not data:
              return
           return data

    def shoot(self, data: bytes):
             try:
                self.sock.sendall(data)
             except Exception as e:
                self.logger.error(f"During sent [ERROR: {e}]")

    def try_handshake(self):
        data=self.wait_recv_utf8()
        if data.startswith(as_server.HANDSHAKE.decode()):
           self.shoot(as_client.HANDSHAKE)
           data=self.wait_recv_utf8()
           if data.startswith(as_server.CONNECTION_APPROVED.decode()):
              return True
        return False
    def try_auth_passwd(self):
        data = self.wait_recv_utf8()
        if data.startswith(as_server.AUTH_PASSED.decode()):
           return True
        user_passwd = str(input("passwd> "))
        self.shoot(user_passwd.encode())
        check_auth = self.wait_recv_utf8()
        if check_auth.startswith(as_server.AUTH_PASSED.decode()):
           return True
        elif check_auth.startswith(as_server.AUTH_FAILED.decode()):
           return False
    def try_check_and_print_kick_msg(self):
        data = self.wait_recv_utf8()
        if data.startswith(as_server.NO_KICKS.decode()):
           return False
        if data.startswith(as_server.KICK.decode()):
           ran = data.split(':')[1]
           ran1 = ran.split('\n')[0]
           self.logger.critical(f"You have been kicked out by the server [REASON: {ran1}]")
           return True
