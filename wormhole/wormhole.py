import socket
import threading
from loader import Config
import time

class Wormhole:
    def __init__(self, host, port, logger, ticket):
        self.host = host
        self.port = port
        self.logger = logger
        self.confirmation = False
        self.config = Config('security.ini')
        self.m_ticket = ticket
        self.ticket = self.m_ticket.load_for_server()
    def run(self):
        if self.ticket is None:
            return False
        self.logger.info('[WORMHOLE] Wormhole entry point has been running. Waiting for any spaceships...')
        print('[WORMHOLE] Wormhole entry point has been running. Waiting for any spaceships...')
        socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_server.bind((self.host, self.port))
        socket_server.listen(1)
        self.logger.info(f"[WORMHOLE] Listening on {self.host}:{self.port}")
        sock, addr = socket_server.accept()
        self.logger.info(f"[WORMHOLE] Connected from {addr}")
        data = sock.recv(1024)
        if not data:
            sock.close()
            socket_server.close()
            self.confirmation = False
            self.logger.critical("[WORMHOLE] Client down")
            return False
        buffer = data.decode('utf-8')
        self.logger.info(f'[WORMHOLE] Sent with ticket: {buffer}')
        if buffer == self.ticket:
            self.logger.info('[WORMHOLE] Passsed, starting true hss server...')
            sock.sendall(b'Passed, Go ahead !')
            sock.close()
            socket_server.close()
            self.confirmation = True
            return True
        else:
            self.logger.critical(f'[WORMHOLE] Destroy myself and Aborting... Because ticket is inccorrect...')
            sock.sendall(b'Wrong ticket. Aborting HSS server...')
            sock.close()
            socket_server.close()
            self.confirmation = False
            return False
    def check(self):
        return self.confirmation