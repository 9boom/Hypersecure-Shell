import socket
from loader import Config

class BKLoggingClient():
    def __init__(self, logger):
        self.logger = logger
        config = Config('security.ini')
        self.server_host = config.logger_server_cli
        self.server_port = config.logger_port_cli
        self.output_log = config.output_logs
    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.server_host, self.server_port))
            print(f"Connected to {self.server_host}:{self.server_port}")
            self.logger.info(f"[bklogger] Connected to {self.server_host}:{self.server_port}")
            with open(self.output_log, 'a', encoding='utf-8') as f:
                self.logger.info("[bklogger] Running")
                print("Running")
                while True:
                    data = s.recv(1024)
                    if not data:
                        self.logger.critical("[bklogger] Server down")
                        print("Server down !")
                        break
                    f.write(data.decode('utf-8'))
                    f.flush()