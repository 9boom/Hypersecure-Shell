# ROTOCOL HELPER
# ALL COMMUNICATION LOGIC HERE

import heapq
import threading
import time
from threading import Thread
from packets import as_server, as_client
import socket
import json
import os
import sys
import time
import base64
import hashlib
import hmac
import secrets
import struct
import uuid
import server_certificate_manager
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.utils import CryptographyDeprecationWarning
import warnings

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

try:
    from oqs import KeyEncapsulation, Signature
except ImportError:
    print("Quantum cryptography not found. Please run ./setup.py first")
    sys.exit(1)

# Configuration - Post-Quantum Hybrid
QUANTUM_KEM_ALG = "Kyber1024"
QUANTUM_SIG_ALG = "Dilithium3"
CLASSICAL_CURVE = ec.SECP384R1()
SESSION_TIMEOUT = 3600
MAX_MESSAGE_AGE = 30
BUFFER_SIZE = 8192

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()

@dataclass
class SessionInfo:
    socket: socket.socket
    address: tuple
    cipher: 'SimpleAESCipher'
    authenticated: bool
    join_time: float
    session_id: str
    certificate: Optional[x509.Certificate]
    classical_private_key: Optional[ec.EllipticCurvePrivateKey]
    message_nonces: set

class CertificateManager:
    @staticmethod
    def generate_self_signed_cert(subject_name: str, private_key, logger) -> x509.Certificate:
        try:
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "TH"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bangkok"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Bangkok"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Quantum Chat"),
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            ])

            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())

            return cert
        except Exception as e:
            logger.error(f"Generate Self Signed Cert Failed [ERROR: {e}]")
            return None

    @staticmethod
    def verify_certificate(cert: x509.Certificate, trusted_certs: List[x509.Certificate]) -> bool:
        try:
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False
            return True
        except Exception:
            return False

class SimpleAESCipher:
    def __init__(self, master_key: bytes, session_id: str, max_message_age):
        self.master_key = master_key
        self.session_id = session_id
        self.max_message_age = max_message_age
        self.encryption_key = self._derive_key(b"AES_ENCRYPTION")
        self.hmac_key = self._derive_key(b"HMAC_AUTH")

    def _derive_key(self, info: bytes) -> bytes:
        full_info = info + self.session_id.encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"quantum_chat_salt",
            info=full_info,
        )
        return hkdf.derive(self.master_key)

    def encrypt(self, data: str, include_timestamp: bool = True) -> bytes:
        if isinstance(data, str):
            data = data.encode('utf-8')

        timestamp = int(time.time()).to_bytes(8, 'big')
        nonce = secrets.token_bytes(12)
        message_id = uuid.uuid4().bytes

        if include_timestamp:
            payload = timestamp + nonce + message_id + data
        else:
            payload = data

        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, auth_tag = cipher.encrypt_and_digest(payload)

        encrypted_data = nonce + auth_tag + ciphertext
        return base64.b64encode(encrypted_data)

    def decrypt(self, encoded_data: bytes, check_timestamp: bool = True) -> Tuple[str, dict]:
        try:
            data = base64.b64decode(encoded_data)
        except Exception:
            raise ValueError("Invalid base64 encoding")

        if len(data) < 12 + 16:
            raise ValueError("Invalid data length")
            
        nonce = data[:12]
        auth_tag = data[12:28]
        ciphertext = data[28:]

        try:
            cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, auth_tag)
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")

        metadata = {}

        if check_timestamp and len(decrypted) >= 8 + 12 + 16:
            timestamp_bytes = decrypted[:8]
            nonce_bytes = decrypted[8:20]
            message_id = decrypted[20:36]
            actual_data = decrypted[36:]

            message_timestamp = int.from_bytes(timestamp_bytes, 'big')
            current_time = int(time.time())

            if abs(current_time - message_timestamp) > self.max_message_age:
                raise ValueError(f"Message too old: {current_time - message_timestamp} seconds")

            metadata.update({
                'timestamp': message_timestamp,
                'nonce': nonce_bytes,
                'message_id': message_id
            })

            return actual_data.decode('utf-8'), metadata
        else:
            return decrypted.decode('utf-8'), metadata

class HybridKeyExchange:
    def __init__(self):
        self.kem = KeyEncapsulation(QUANTUM_KEM_ALG)
        self.classical_private_key = ec.generate_private_key(CLASSICAL_CURVE)
        self.kem_public_key = self.kem.generate_keypair()

    def get_public_keys(self) -> Tuple[bytes, bytes]:
        classical_public_bytes = self.classical_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return self.kem_public_key, classical_public_bytes

    def derive_shared_secret(self, kem_ciphertext: bytes, peer_classical_public: bytes) -> bytes:
        pq_secret = self.kem.decap_secret(kem_ciphertext)

        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            CLASSICAL_CURVE, peer_classical_public
        )
        classical_secret = self.classical_private_key.exchange(
            ec.ECDH(), peer_public_key
        )

        combined_secret = pq_secret + classical_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hybrid_kdf_salt",
            info=b"post_quantum_classical_hybrid",
        )

        return hkdf.derive(combined_secret)

class ServerManager:
    def __init__(self, logger, client_socket, addr, buffer_size, max_messaage_age, password_to_login):
        self.logger = logger
        self.client_socket = client_socket
        self.addr = addr
        self.buffer_size = buffer_size
        self.password_to_login = password_to_login
        self.max_message_age = max_messaage_age
        self.session: Optional[SessionInfo] = None
        self.server_cert_manager = server_certificate_manager.ServerCertificateManager(self.logger)

        self.key_exchange = HybridKeyExchange()
        self.sig = Signature(QUANTUM_SIG_ALG)
        self.sig_public_key = self.sig.generate_keypair()
        self.server_cert = self.server_cert_manager.init(CLASSICAL_CURVE, CertificateManager)
        
        self.client_id = f"{addr[0]}:{addr[1]}_{int(time.time())}"

        self.logger.info(f"[Quantum Protocol] Using Hybrid {QUANTUM_KEM_ALG} + ECDH")
        self.logger.info(f"[Quantum Protocol] Signature Algorithm: {QUANTUM_SIG_ALG}")

    def send_large_data(self, sock: socket.socket, data: bytes):
        length = len(data)
        sock.sendall(struct.pack('!I', length))
        sock.sendall(data)

    def receive_large_data(self, sock: socket.socket) -> bytes:
        length_data = b''
        while len(length_data) < 4:
            chunk = sock.recv(4 - len(length_data))
            if not chunk:
                raise ConnectionError("Connection closed")
            length_data += chunk
            
        length = struct.unpack('!I', length_data)[0]
        data = b''
        while len(data) < length:
            chunk = sock.recv(min(self.buffer_size, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def handshake(self):
        try:
            session_id = str(uuid.uuid4())

            # 1. Send Server Info and Challenge
            kem_pub, classical_pub = self.key_exchange.get_public_keys()
            server_challenge = secrets.token_bytes(32)

            server_info = {
                "session_id": session_id,
                "kem_public_key": base64.b64encode(kem_pub).decode(),
                "classical_public_key": base64.b64encode(classical_pub).decode(),
                "sig_public_key": base64.b64encode(self.sig_public_key).decode(),
                "server_challenge": base64.b64encode(server_challenge).decode(),
                "certificate": base64.b64encode(
                    self.server_cert.public_bytes(serialization.Encoding.DER)
                ).decode()
            }

            server_info_data = json.dumps(server_info).encode('utf-8')
            self.send_large_data(self.client_socket, server_info_data)

            # 2. Receive Client Response
            response_data = self.receive_large_data(self.client_socket)
            client_response = json.loads(response_data.decode('utf-8'))

            # Verify certificate
            client_cert = None
            if "certificate" in client_response and client_response["certificate"]:
                cert_data = base64.b64decode(client_response["certificate"])
                client_cert = x509.load_der_x509_certificate(cert_data)
                if not CertificateManager.verify_certificate(client_cert, []):
                    raise ValueError("Client certificate verification failed")

            # Verify Digital Signature
            challenge_response = base64.b64decode(client_response["challenge_response"])
            signature = base64.b64decode(client_response["signature"])
            client_sig_public_key = base64.b64decode(client_response["client_sig_public_key"])

            client_sig = Signature(QUANTUM_SIG_ALG)
            if not client_sig.verify(challenge_response, signature, client_sig_public_key):
                raise ValueError("Client signature verification failed")

            # 3. Hybrid Key Exchange
            kem_ciphertext = base64.b64decode(client_response["kem_ciphertext"])
            client_classical_public = base64.b64decode(client_response["client_classical_public"])

            shared_secret = self.key_exchange.derive_shared_secret(
                kem_ciphertext, client_classical_public
            )

            self.logger.info(f"[Quantum Protocol] Hybrid key exchange successful")
            self.logger.info(f"[Quantum Protocol] Shared secret size: {len(shared_secret)} bytes")

            # Create Session
            cipher = SimpleAESCipher(shared_secret, session_id, self.max_message_age)
            current_time = time.time()

            self.session = SessionInfo(
                socket=self.client_socket,
                address=self.addr,
                cipher=cipher,
                authenticated=True,
                join_time=current_time,
                session_id=session_id,
                certificate=client_cert,
                classical_private_key=self.key_exchange.classical_private_key,
                message_nonces=set()
            )

            # Send confirmation message
            welcome_msg = f"Connection secured successfully | Session ID: {session_id}"
            encrypted_welcome = cipher.encrypt(welcome_msg)
            self.send_large_data(self.client_socket, encrypted_welcome)

            self.logger.info(f"[DEBUG] Session ID: {session_id}")
            self.logger.info(f"[DEBUG] Master key (shared secret): {shared_secret.hex()}")


        except Exception as e:
            self.logger.error(f"[Quantum Protocol] Handshake failed for {self.client_id}: {e}")
            self.disconnect_client()
            try:
                self.client_socket.close()
            except:
                pass
            raise

    def disconnect_client(self):
        if self.session:
            try:
                self.session.socket.close()
            except:
                pass
            self.logger.info(f"[Quantum Protocol] Closed connection: {self.client_id}")
            self.session = None

    def cleanup(self):
        self.disconnect_client()
        self.logger.info("[Quantum Protocol] Server closed")

    def return_sock(self):
        return self.client_socket

    def return_addr(self):
        return self.addr

    def try_handshake(self):
        self.logger.info("Waiting for quantum handshake...")
        try:
            self.handshake()
            return True
        except Exception as e:
            self.logger.critical(f"Quantum Handshake failed: {e}")
            return False

    def kick(self, reason):
        if self.session:
           try:
               msg = as_server.KICK + reason.encode() + b'\n'
               encrypted_msg = self.session.cipher.encrypt(msg, include_timestamp=False)
               self.send_large_data(self.session.socket, encrypted_msg)
           except:
               pass
        time.sleep(2)
        self.disconnect_client()

    def disconnect(self):
        self.cleanup()

    def req_passwd(self, enable=True):
        if self.session is None:
           return False

        if enable:
           time.sleep(1)
           encrypted_request = self.session.cipher.encrypt(as_server.PASSWORD_REQUEST, include_timestamp=False)
           self.send_large_data(self.session.socket, encrypted_request)
           try:
               data = self.receive_large_data(self.session.socket)
               decrypted, _ = self.session.cipher.decrypt(data)
               if decrypted.startswith(as_client.PASSWORD.decode()):
                  user_passwd = decrypted.split(':', 1)[1].strip()
                  self.logger.info(f"IP: {self.addr} Login using the password '{user_passwd}'")
                  if user_passwd == self.password_to_login:
                     encrypted_pass = self.session.cipher.encrypt(as_server.AUTH_PASSED, include_timestamp=False)
                     self.send_large_data(self.session.socket, encrypted_pass)
                     return True
                  else:
                     encrypted_fail = self.session.cipher.encrypt(as_server.AUTH_FAILED, include_timestamp=False)
                     self.send_large_data(self.session.socket, encrypted_fail)
                     return False
           except Exception as e:
                  self.logger.warning(f"Password auth failed: {e}")
                  return False
        else:
            time.sleep(1)
            encrypted_pass = self.session.cipher.encrypt(as_server.AUTH_PASSED, include_timestamp=False)
            self.send_large_data(self.session.socket, encrypted_pass)
            return True
            
    def no_kicks(self):
        if self.session:
           try:
              encrypted_msg = self.session.cipher.encrypt(as_server.NO_KICKS, include_timestamp=False)
              self.send_large_data(self.session.socket, encrypted_msg)
           except:
              pass

    def bye(self):
        if self.session:
           try:
              encrypted_msg = self.session.cipher.encrypt(as_server.BYE, include_timestamp=False)
              self.send_large_data(self.session.socket, encrypted_msg)
           except:
              pass

    def oshell(self, data):
        if self.session:
           try:
              encrypted = self.session.cipher.encrypt(data, include_timestamp=False)
              self.send_large_data(self.session.socket, encrypted)
           except:
              pass

    def wait_recv_utf8(self):
        if self.session is None:
            return None
            
        try:
            data = self.receive_large_data(self.session.socket)
            if not data:
                self.logger.info(f"[SERVER] {self.client_id} closed connection")
                self.disconnect_client()
                return None

            try:
                decrypted_message, metadata = self.session.cipher.decrypt(data)

                # Check replay protection
                if 'message_id' in metadata:
                    message_id = metadata['message_id']
                    if message_id in self.session.message_nonces:
                        self.logger.warning(f"[SERVER] Replay attack detected from {self.client_id}")
                        return None
                    self.session.message_nonces.add(message_id)

                    if len(self.session.message_nonces) > 1000:
                        self.session.message_nonces.clear()

                return decrypted_message
            except ValueError as e:
                self.logger.error(f"[SERVER] Decryption failed: {e}")
                return None

        except Exception as e:
            self.logger.error(f"[SERVER] Receive error: {e}")
            self.disconnect_client()
            return None

class ClientManager:
    def __init__(self, logger, client_socket,buffer_size, max_message_age, password):
        self.max_message_age = max_message_age
        self.password = password
        self.logger = logger
        self.client_socket = client_socket
        self.username = 'test123122312121'
        self.buffer_size = buffer_size
        
        self.key_exchange = HybridKeyExchange()
        self.sig = Signature(QUANTUM_SIG_ALG)
        self.sig_public_key = self.sig.generate_keypair()

        self.client_cert_key = ec.generate_private_key(CLASSICAL_CURVE)
        self.client_cert = CertificateManager.generate_self_signed_cert(
            f"Quantum Chat Client - {self.username}", self.client_cert_key, self.logger
        )

        self.cipher = None
        self.connected = False
        self.session_id = None

    def send_large_data(self, data: bytes):
        length = len(data)
        self.client_socket.sendall(struct.pack('!I', length))
        self.client_socket.sendall(data)

    def receive_large_data(self) -> bytes:
        length_data = b''
        while len(length_data) < 4:
            chunk = self.client_socket.recv(4 - len(length_data))
            if not chunk:
                raise ConnectionError("Connection closed")
            length_data += chunk
            
        length = struct.unpack('!I', length_data)[0]
        data = b''
        while len(data) < length:
            chunk = self.client_socket.recv(min(self.buffer_size, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def handshake(self):
        try:
            server_data = self.receive_large_data()
            server_info = json.loads(server_data.decode('utf-8'))
            self.session_id = server_info["session_id"]
            server_kem_public = base64.b64decode(server_info["kem_public_key"])
            server_classical_public = base64.b64decode(server_info["classical_public_key"])
            server_sig_public = base64.b64decode(server_info["sig_public_key"])
            server_challenge = base64.b64decode(server_info["server_challenge"])
            server_cert = None
            if server_info.get("certificate"):
                cert_data = base64.b64decode(server_info["certificate"])
                server_cert = x509.load_der_x509_certificate(cert_data)
                if not CertificateManager.verify_certificate(server_cert, []):
                    self.logger.error("[Quantum Protocol] Warning: Server certificate verification failed")
            if server_cert:
                fingerprint = get_cert_fingerprint(server_cert)
                trusted_fingerprint_file = ".config/client/trusted_server_fingerprint.txt"
                trusted_fingerprint = None
                if os.path.exists(trusted_fingerprint_file):
                    with open(trusted_fingerprint_file, "r") as f:
                        trusted_fingerprint = f.read().strip()
                if trusted_fingerprint is None:
                    os.makedirs(os.path.dirname(trusted_fingerprint_file), exist_ok=True)
                    with open(trusted_fingerprint_file, "w") as f:
                        f.write(fingerprint)
                    self.logger.info(f"[Quantum Protocol] Trusted new server cert, fingerprint: {fingerprint}")
                else:
                    if fingerprint != trusted_fingerprint:
                        self.logger.error(f"[Quantum Protocol] Server cert fingerprint mismatch")
                        raise ValueError("Server certificate verification failed")
                    else:
                        self.logger.info(f"[Quantum Protocol] fingerprint OK: {fingerprint}")
            self.logger.info(f"[Quantum Protocol] Established session: {self.session_id}")
            client_kem_pub, client_classical_pub = self.key_exchange.get_public_keys()
            kem = KeyEncapsulation(QUANTUM_KEM_ALG)
            kem_ciphertext, pq_secret = kem.encap_secret(server_kem_public)
            server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                CLASSICAL_CURVE, server_classical_public
            )
            classical_secret = self.key_exchange.classical_private_key.exchange(
                ec.ECDH(), server_public_key
            )
            combined_secret = pq_secret + classical_secret
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"hybrid_kdf_salt",
                info=b"post_quantum_classical_hybrid",
            )
            shared_secret = hkdf.derive(combined_secret)
            challenge_response = server_challenge + b"client_response_" + self.session_id.encode()
            signature = self.sig.sign(challenge_response)
            client_response = {
                "kem_ciphertext": base64.b64encode(kem_ciphertext).decode(),
                "client_classical_public": base64.b64encode(client_classical_pub).decode(),
                "challenge_response": base64.b64encode(challenge_response).decode(),
                "signature": base64.b64encode(signature).decode(),
                "client_sig_public_key": base64.b64encode(self.sig_public_key).decode(),
                "certificate": base64.b64encode(
                    self.client_cert.public_bytes(serialization.Encoding.DER)
                ).decode() if self.client_cert else None
            }
            client_response_data = json.dumps(client_response).encode('utf-8')
            self.send_large_data(client_response_data)
            self.cipher = SimpleAESCipher(shared_secret, self.session_id, self.max_message_age)
            self.logger.info(f"[Quantum Protocol] Hybrid key exchange successful")
            welcome = self.receive_large_data()
            if welcome:
                try:
                    msg, _ = self.cipher.decrypt(welcome)
                    self.logger.info(f"[Server] {msg}")
                except:
                    pass
            self.connected = True
            self.logger.info(f"[DEBUG] Session ID: {self.session_id}")
            self.logger.info(f"[DEBUG] Master key (shared secret): {shared_secret.hex()}")
        except Exception as e:
            self.logger.info(f"[Quantum Protocol] Handshake error: {e}")
            self.disconnect()
            raise
    def disconnect(self):
        self.connected = False
        try:
            self.client_socket.close()
        except:
            pass
        self.logger.info("\n[Quantum Protocol] Disconnected")

    def return_sock(self):
        return self.client_socket

    def start(self):
        pass

    def send_message(self, message: str):
        try:
            if message.strip() and self.connected:
                encrypted_message = self.cipher.encrypt(message)
                self.send_large_data(encrypted_message)
        except Exception as e:
            self.logger.critical(f"[CLIENT] Send error: {e}")

    def try_handshake(self):
        self.logger.info("Performing quantum handshake...")
        print("If you encounter errors, try running with --force")
        try:
            self.handshake()
            return True
        except Exception as e:
            self.logger.critical(f"[Quantum Protocol] Handshake failed: {e}")
            return False

    def try_auth_passwd(self):
        try:
            data = self.wait_recv_utf8()
            if data and data.startswith(as_server.AUTH_PASSED.decode()):
                return True
            if self.password.startswith('ASK_EVERY_TIME'):
                user_passwd = input("[AUTH] Enter password > ")
            else:
                self.logger.info("[AUTH] Auto Fill from security.ini...")
                print("[AUTH] Auto Fill from security.ini...")
                user_passwd = self.password
            self.send_message(as_client.PASSWORD.decode() + user_passwd + '\n')
            
            resp = self.wait_recv_utf8()
            if resp and resp.startswith(as_server.AUTH_PASSED.decode()):
                self.logger.info("Authentication passed, Wait a moment...")
                return True
            elif resp and resp.startswith(as_server.AUTH_FAILED.decode()):
                return False
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
        return False

    def try_check_and_print_kick_msg(self):
        try:
            data = self.wait_recv_utf8()
            if data and data.startswith(as_server.NO_KICKS.decode()):
                return False
            if data and data.startswith(as_server.KICK.decode()):
                reason = data.split(':', 1)[1].strip()
                self.logger.critical(f"Kicked by server [REASON: {reason}]")
                return True
        except:
            pass
        return False

    def shell(self, cmd_exec):
        self.send_message(as_client.SHELL.decode() + cmd_exec.decode() + '\n')

    def resize(self, rows: str, cols: str):
        self.send_message(as_client.RESIZE.decode() + f"{rows}:{cols}\n")

    def wait_recv_utf8(self):
        try:
            data = self.receive_large_data()
            if not data:
                self.logger.info("[CLIENT] Server disconnected")
                self.disconnect()
                return None
            try:
                decrypted_message, metadata = self.cipher.decrypt(data, check_timestamp=False)
                return decrypted_message
            except ValueError as e:
                self.logger.critical(f"[CLIENT] Decryption failed: {e}")
                return None

        except Exception as e:
            if self.connected:
                self.logger.critical(f"[CLIENT] Receive error: {e}")
            return None
