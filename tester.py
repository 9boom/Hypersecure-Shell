import socket
from quantum_protocol import QuantumSecureServer
from quantum_protocol import QuantumSecureClient

def server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1',9000))
    sock.listen(5)
    while True:
          csock, addr = sock.accept()
          session=QuantumSecureServer()
          session.start(csock,addr)
def client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1',9000))
    session = QuantumSecureClient('Boom')
    session.connect(sock)
client()
