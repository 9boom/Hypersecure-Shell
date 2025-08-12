import socket
import random
import hashlib
from packets import as_server

class ZKP2():
    def __init__(self, self2, user_passwd, logger):
        self.self2 = self2
        self.logger = logger
        self.password = user_passwd
        self.P = 2**521 - 1
        self.X_hash = hashlib.sha512(self.password.encode()).hexdigest()
        self.X = int(self.X_hash, 16) % self.P
    def check(self):
        print('NOTE: This process may take several minutes. If the connection is unstable and any error occurs, please lower the ZKP_num_round value on server in security.ini')
        self.logger.info("[zkp] verify")
        nrr = self.self2.wait_recv_utf8()
        if nrr.startswith(as_server.ZKP_NUM_ROUND.decode()):
            NUM_ROUNDS = int(nrr[len(as_server.ZKP_NUM_ROUND.decode()):])
        else:
            self.logger.error("[zkp] Reading ZKP_NUM_ROUND protocol flag failed. set default to 300")
            NUM_ROUNDS = 300
        for i in range(NUM_ROUNDS):
            self.logger.info(f"[zkp] Verify process: Round {i+1}/{NUM_ROUNDS}")
            cal = (i/NUM_ROUNDS) * 100
            print(f"[zkp] verifying {i} rounds : {int(cal)} %", flush = True, end ='\r')
            R = random.randint(1, self.P - 1)
            A = pow(R, 2, self.P)
            self.self2.send_message(str(A))
            c_raw = self.self2.wait_recv_utf8()
            if c_raw.startswith(as_server.ZKP_FAILED.decode()):
                return
            c = int(c_raw)
            if c == 0:
                self.self2.send_message(str(R))
            else:
                S = (R * self.X) % self.P
                self.self2.send_message(str(S))