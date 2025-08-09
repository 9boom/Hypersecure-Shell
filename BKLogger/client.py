import socket

SERVER_HOST = '192.168.x.x'  # IP ของ main system
SERVER_PORT = 5000
OUTPUT_LOG = 'backup_server.log'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((SERVER_HOST, SERVER_PORT))
    print(f"[CLIENT] Connected to {SERVER_HOST}:{SERVER_PORT}")

    with open(OUTPUT_LOG, 'a', encoding='utf-8') as f:
        while True:
            data = s.recv(1024)
            if not data:
                break
            f.write(data.decode('utf-8'))
            f.flush()
