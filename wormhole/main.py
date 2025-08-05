import socket
import threading

class Wormhole:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.running = True

    def run(self):
        socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_server.bind((self.host, self.port))
        socket_server.listen(1)
        print(f"Listening on {self.host}:{self.port}")
        sock, addr = socket_server.accept()
        print(f"Connected from {addr}")
        data = sock.recv(1024)
        if not data:
            socket_server.close()
            return False
        buffer = data.decode('utf-8')
        if buffer.startswith('password'):
            socket_server.close()
            return True
        else:
            socket_server.close()
            return False