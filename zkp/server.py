import socket
import random
import hashlib
from packets import as_server
import time

class ZKP1():
    def __init__(self, self2, logger):
        self.logger = logger
        self.self2 = self2
        self.P = 2**521 - 1
        self.password = self.self2.password_to_login
        self.X_hash = hashlib.sha512(self.password.encode()).hexdigest()
        self.X = int(self.X_hash, 16) % self.P
        self.Y = pow(self.X, 2, self.P)
    def check(self):
        self.logger.info("[zkp] Zero Knowleged Proof Verification Started")
        nrr = self.self2.session.cipher.encrypt(as_server.ZKP_NUM_ROUND.decode()+str(self.self2.zkp_num_round) + '\n', include_timestamp=False)
        self.self2.send_large_data(self.self2.session.socket, nrr)
        self.logger.info("[zkp] Sent ZKP_NUM_ROUND flag !")
        self.logger.info("[zkp] verifying...")
        for i in range(self.self2.zkp_num_round):
            A = int(self.self2.wait_recv_utf8())
            c = random.randint(0, 1)
            raw = self.self2.session.cipher.encrypt(str(c),include_timestamp=False)
            self.self2.send_large_data(self.self2.session.socket, raw)
            response = self.self2.wait_recv_utf8()
            if not self.verify_proof(A, c, response):
                raw2 = self.self2.session.cipher.encrypt(as_server.ZKP_FAILED.decode(), include_timestamp=False)
                self.self2.send_large_data(self.self2.session.socket, raw2)
                self.logger.info(f"Verification failed at round {i+1}")
                return False
        self.logger.info('[zkp] verified... Go ahead !')
        return True
    def verify_proof(self, A, c, response):
        if c == 0:
            R = int(response)
            return A == pow(R, 2, self.P)
        else:
            S = int(response)
            return pow(S, 2, self.P) == (A * self.Y) % self.P