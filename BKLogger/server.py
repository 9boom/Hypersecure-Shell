import socket
import os
import time
from loader import Config
from pathlib import Path

class BKLoggingServer:
    def __init__(self, logger):
        self.logger = logger
        config = Config('security.ini')
        self.host = config.logger_server
        self.port = config.logger_port
        self.chunk_size = config.chunk_size
        self.refresh_time = config.refresh_time
        self.cache_file_fol = Path('.cache')
        self.cache_file = self.cache_file_fol / "server.log.cache"
        self.log_file_fol = Path('outputs/logs')
        self.log_file = self.log_file_fol / 'server.log'        
    def save_cache(self, data:str):
        with open(self.cache_file, 'w') as  f:
            f.write(data)
            f.close()
    def load_cache(self):
        data = None
        with open(self.cache_file, 'r') as f:
            data = f.read()
            f.close()            
        return data
    def load_log(self):
        data = None
        with open(self.log_file, 'r') as f:
            data = f.read()
            f.close()            
        return data
    def start(self):
        cache = ''
        backall_q = ''
        self.cache_file_fol.mkdir(parents=True, exist_ok=True)
        if self.cache_file_fol.exists() and self.cache_file.exists():        
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                cache = f.read()
                f.close()
        else:
            try:
                with open(self.log_file, 'r') as f:
                    data = f.read()
                    f.close()
                    with open(self.cache_file, 'w') as f:
                        f.write(data)
                        f.close()
            except Exception as e:
                print(f"[bklogger] Something wrong While try to load log file and save cache [ERROR: {e}]")
                self.logger.error(f"[bklogger] Something wrong While try to load log file and save cache [ERROR: {e}]")

            backall_q = str(input("[Do you want to send all previous logs to the bklogger-to ? (Effective when you run the bklogger-to from the computer you will backup)][yn] "))
            backall_q = backall_q.lower()
            self.logger.info(f"[bklogger] backall_q got {backall_q} key")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(1)
            print(f"[bklogger] Listening on port {self.port}...")
            self.logger.info(f"[bklogger] Listening on port {self.port}...")

            conn, addr = s.accept()
            with conn:
                print(f"[bklogger] Connected by {addr}")
                self.logger.info(f"[bklogger] Connected by {addr}")
                if backall_q == 'y':
                    print("[bklogger] Backup all previous logs to bklogger-to...")
                    self.logger.info("[bklogger] Backup all previous logs to bklogger-to...")
                    data = self.load_log()
                    self.send_in_chunks(conn, data)
                while True:
                    try:
                        data = self.load_log()
                        self.cache = self.load_cache()
                        if data != self.cache:
                            a = data[len(self.cache):]
                            self.send_in_chunks(conn, a)
                            self.save_cache(data)
                        time.sleep(self.refresh_time)
                    except (ConnectionResetError, BrokenPipeError) as e:
                        conn.close()
                        s.close()
                        print(f"[bklogger] Connection lost. Aborting... [CRITICAL: {e}]")
                        self.logger.critical(f"[bklogger] Connection lost. Aborting... [CRITICAL: {e}]")
                        break
                conn.close()
            s.close()
    def send_in_chunks(self, conn, data):
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i+self.chunk_size]
            conn.sendall(chunk.encode('utf-8'))