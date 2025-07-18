import socket
import random
import hashlib

# จำนวนเฉพาะขนาดใหญ่ (Mersenne prime)
P = 2**521 - 1
NUM_ROUNDS = 300

# รับ password จากผู้ใช้ แล้วแปลงเป็นค่า X แบบ deterministic
password = input("Enter your password: ")
X_hash = hashlib.sha512(password.encode()).hexdigest()
X = int(X_hash, 16) % P  # แปลงเป็นเลขจำนวนเต็มในช่วง 0 - P-1

client = socket.socket()
client.connect(('localhost', 7777))

print("[zkp] verify...")
for i in range(NUM_ROUNDS):
    #print(f"--- Round {i+1}/{NUM_ROUNDS} ---")

    R = random.randint(1, P - 1)
    A = pow(R, 2, P)
    client.send(str(A).encode())

    #c = int(client.recv(1024).decode())
    c_raw = client.recv(1024).decode()
    if c_raw == "FAIL":
       print("\nServer says: Authentication failed.")
       client.close()
       exit()
    c = int(c_raw)

    if c == 0:
        client.send(str(R).encode())
    else:
        S = (R * X) % P
        client.send(str(S).encode())

result = client.recv(1024).decode()

if result == "SUCCESS":
    print("\nAuthentication passed. Access granted!")
else:
    print("\nAuthentication failed.")
client.close()
