import socket
import random
import hashlib

P = 2**521 - 1
NUM_ROUNDS = 300
password = "pongsakorn2008"  # Server ควรรู้รหัสผ่านของผู้ใช้ล่วงหน้า

# แปลง password เป็น X และ Y
X_hash = hashlib.sha512(password.encode()).hexdigest()
X = int(X_hash, 16) % P
Y = pow(X, 2, P)

PORT = 7777

def verify_proof(A, c, response):
    if c == 0:
        R = int(response)
        return A == pow(R, 2, P)
    else:
        S = int(response)
        return pow(S, 2, P) == (A * Y) % P

server = socket.socket()
server.bind(('localhost', PORT))
server.listen(10)
print("Server ready. Waiting for client...")
while 1:
    conn, _ = server.accept()
    print("Client connected.\n")

    for i in range(NUM_ROUNDS):
        A = int(conn.recv(1024).decode())
        c = random.randint(0, 1)
        conn.send(str(c).encode())
        response = conn.recv(1024).decode()

        if not verify_proof(A, c, response):
           conn.send(b'FAIL')
           print(f"Verification failed at round {i+1}")
           conn.close()
           exit()
    conn.send(b'SUCCESS')
    print("\nClient authenticated successfully!")
