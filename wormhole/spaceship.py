import socket
from loader import Config
import time

class Spaceship():
    def __init__(self, logger, ticket):
        self.config = Config('security.ini')
        self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.remote.settimeout(int(self.config.remote_wormhole_timeout))
        self.logger = logger
        self.ticket = ticket
        self.host = None
        self.port = None
    def shoot(self):
        data = self.read_ticket()
        if data is None:
            return 'Aborting...'
        try:
            self.remote.connect((str(self.host), int(self.port)))
        except Exception as e:
            self.logger.critical(f"[WORMHOLE] Failed to connect [CRITICAL: {e}]")
            return 'This ticket is not working...'
        time.sleep(1)
        self.remote.sendall(data.encode('utf-8'))
        data = self.remote.recv(1024)
        if not data:
            self.logger.info("[WORMHOLE] Wormhole server down")
            return "[WORMHOLE] Wormhole server down error"
        return data.decode()
    def read_ticket(self):
        data=self.ticket.load()
        if data is None:
            return None
        addr = str(data)
        addr = addr.split('%')
        self.host = addr[0]
        self.port = addr[1]
        return str(data)
            