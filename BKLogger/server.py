import socket
import os
import time

class LogBackupServer:
    def __init__(self, host='', port=5000, chunk_size=1024,
                 log_file='outputs/logs/server.log',
                 cache_file='.cache/server.log.cache'):
        self.host = host
        self.port = port
        self.chunk_size = chunk_size
        self.log_file = log_file
        self.cache_file = cache_file
        self.cache = self.load_cache()
    def load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                return f.read()
        return ''
    def update_cache(self, data):
        with open(self.cache_file, 'w', encoding='utf-8') as f:
            f.write(data)
        self.cache = data
    def get_new_log_data(self):
        with open(self.log_file, 'r', encoding='utf-8') as f:
            data = f.read()
        if data != self.cache:
            return data[len(self.cache):] if data.startswith(self.cache) else data, data
        return None, data
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(1)
            print(f"[SERVER] Listening on port {self.port}...")
            conn, addr = s.accept()
            with conn:
                print(f"[SERVER] Connected by {addr}")
                while True:
                    try:
                        new_data, full_data = self.get_new_log_data()
                        if new_data:
                            self.send_in_chunks(conn, new_data)
                            self.update_cache(full_data)
                        time.sleep(1)
                    except (ConnectionResetError, BrokenPipeError):
                        print("[SERVER] Connection lost. Waiting for client...")
                        break
    def send_in_chunks(self, conn, data):
        for i in range(0, len(data), self.chunk_size):
            chunk = data[i:i+self.chunk_size]
            conn.sendall(chunk.encode('utf-8'))