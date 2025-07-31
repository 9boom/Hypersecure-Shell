# PROTOCOL HELPER
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

try:
    from oqs import KeyEncapsulation, Signature
except ImportError:
    print("Quantum cryptography not found. Please run ./setup.py first")
    sys.exit(1)

# Configuration - Post-Quantum Hybrid
QUANTUM_KEM_ALG = "Kyber1024"
QUANTUM_SIG_ALG = "Dilithium3"
CLASSICAL_CURVE = ec.SECP384R1()
KEY_ROTATION_INTERVAL = 60  # 5 minutes
SESSION_TIMEOUT = 3600
MAX_MESSAGE_AGE = 30
BUFFER_SIZE = 8192

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()

@dataclass
class SessionInfo:
    socket: socket.socket
    address: tuple
    cipher: 'EnhancedAESCipher'
    authenticated: bool
    join_time: float
    last_key_rotation: float
    session_id: str
    certificate: Optional[x509.Certificate]
    classical_private_key: Optional[ec.EllipticCurvePrivateKey]
    message_nonces: set
    new_key_exchange: Optional['HybridKeyExchange'] = None

class CertificateManager:
    @staticmethod
    def generate_self_signed_cert(subject_name: str, private_key) -> x509.Certificate:
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
            print(f"Failed to create certificate: {e}")
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

class EnhancedAESCipher:
    def __init__(self, master_key: bytes, session_id: str):
        self.master_key = master_key
        self.session_id = session_id
        self.current_key_version = 0
        self.key_history = {}
        self._rotate_keys()

    def _derive_key(self, info: bytes, key_version: int = None) -> bytes:
        if key_version is None:
            key_version = self.current_key_version

        full_info = info + self.session_id.encode() + key_version.to_bytes(4, 'big')

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"quantum_chat_salt",
            info=full_info,
        )
        return hkdf.derive(self.master_key)

    def _rotate_keys(self):
        if self.current_key_version > 0:
            old_enc_key = self._derive_key(b"AES_ENCRYPTION", self.current_key_version - 1)
            old_hmac_key = self._derive_key(b"HMAC_AUTH", self.current_key_version - 1)
            self.key_history[self.current_key_version - 1] = {
                'encryption': old_enc_key,
                'hmac': old_hmac_key,
                'timestamp': time.time()
            }

        self.current_key_version += 1
        self.encryption_key = self._derive_key(b"AES_ENCRYPTION")
        self.hmac_key = self._derive_key(b"HMAC_AUTH")

        current_time = time.time()
        expired_versions = [
            v for v, data in self.key_history.items()
            if current_time - data['timestamp'] > 300
        ]
        for v in expired_versions:
            del self.key_history[v]

    def encrypt(self, data: str, include_timestamp: bool = True) -> bytes:
        if isinstance(data, str):
            data = data.encode('utf-8')

        timestamp = int(time.time()).to_bytes(8, 'big')
        nonce = secrets.token_bytes(16)
        message_id = uuid.uuid4().bytes

        if include_timestamp:
            payload = timestamp + nonce + message_id + data
        else:
            payload = data

        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, auth_tag = cipher.encrypt_and_digest(payload)

        encrypted_data = (
            self.current_key_version.to_bytes(4, 'big') +
            nonce + auth_tag + ciphertext
        )

        mac = hmac.new(self.hmac_key, encrypted_data, hashlib.sha256).digest()

        return base64.b64encode(mac + encrypted_data)

    def decrypt(self, encoded_data: bytes, check_timestamp: bool = True) -> Tuple[str, dict]:
        try:
            data = base64.b64decode(encoded_data)
        except Exception:
            raise ValueError("Invalid base64 encoding")

        if len(data) < 32:
            raise ValueError("Invalid data length")
        mac = data[:32]
        encrypted_data = data[32:]

        if len(encrypted_data) < 4:
            raise ValueError("Invalid key version length")
        key_version = int.from_bytes(encrypted_data[:4], 'big')
        encrypted_data = encrypted_data[4:]

        if key_version == self.current_key_version:
            enc_key = self.encryption_key
            hmac_key = self.hmac_key
        elif key_version in self.key_history:
            enc_key = self.key_history[key_version]['encryption']
            hmac_key = self.key_history[key_version]['hmac']
        else:
            raise ValueError(f"Key version {key_version} not found")

        full_data = key_version.to_bytes(4, 'big') + encrypted_data
        expected_mac = hmac.new(hmac_key, full_data, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification failed")
            
        if len(encrypted_data) < 32:
            raise ValueError("Invalid encrypted data length")
        nonce = encrypted_data[:16]
        auth_tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]

        try:
            cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
            decrypted = cipher.decrypt_and_verify(ciphertext, auth_tag)
        except ValueError as e:
            raise ValueError(f"Decryption failed: {str(e)}")

        metadata = {'key_version': key_version}

        if check_timestamp and len(decrypted) >= 40:
            timestamp_bytes = decrypted[:8]
            nonce_bytes = decrypted[8:24]
            message_id = decrypted[24:40]
            actual_data = decrypted[40:]

            message_timestamp = int.from_bytes(timestamp_bytes, 'big')
            current_time = int(time.time())

            if abs(current_time - message_timestamp) > MAX_MESSAGE_AGE:
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
    def __init__(self, logger, client_socket, addr):
        self.logger = logger
        self.client_socket = client_socket
        self.addr = addr
        self.session: Optional[SessionInfo] = None
        self.server_cert_manager = server_certificate_manager.ServerCertificateManager()

        self.key_exchange = HybridKeyExchange()
        self.sig = Signature(QUANTUM_SIG_ALG)
        self.sig_public_key = self.sig.generate_keypair()
        self.server_cert = self.server_cert_manager.init(CLASSICAL_CURVE, CertificateManager)
        
        self.key_rotation_timer = None
        self.start_key_rotation_timer()

        self.client_id = f"{addr[0]}:{addr[1]}_{int(time.time())}"

        print(f"[Quantum Protocol] Using Hybrid {QUANTUM_KEM_ALG} + ECDH")
        print(f"[Quantum Protocol] Signature Algorithm: {QUANTUM_SIG_ALG}")
        print(f"[Quantum Protocol] Key Rotation: every {KEY_ROTATION_INTERVAL} seconds")

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
            chunk = sock.recv(min(BUFFER_SIZE, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def start_key_rotation_timer(self):
        def rotate_key():
            if self.session is None:
                return
                
            current_time = time.time()
            try:
                # Rotate key if time exceeded
                if current_time - self.session.last_key_rotation > KEY_ROTATION_INTERVAL:
                    self.initiate_key_rotation()
                    self.session.last_key_rotation = current_time
                    print(f"!!!! ROTATE KEY for {self.client_id} !!!!")

                # Check session timeout
                if current_time - self.session.join_time > SESSION_TIMEOUT:
                    print(f"[Quantum Protocol] Session timeout: {self.client_id}")
                    self.disconnect_client()

            except Exception as e:
                print(f"[Quantum Protocol] Failed to rotate key for {self.client_id}: {e}")
                self.disconnect_client()

            # Reset timer only if session still exists
            if self.session:
                self.key_rotation_timer = threading.Timer(60, rotate_key)
                self.key_rotation_timer.daemon = True
                self.key_rotation_timer.start()

        # Start initial timer
        self.key_rotation_timer = threading.Timer(60, rotate_key)
        self.key_rotation_timer.daemon = True
        self.key_rotation_timer.start()

    def initiate_key_rotation(self):
        if self.session is None:
            return
            
        try:
            new_key_exchange = HybridKeyExchange()
            kem_pub, classical_pub = new_key_exchange.get_public_keys()

            rotation_request = {
                "type": "key_rotation",
                "kem_public_key": base64.b64encode(kem_pub).decode(),
                "classical_public_key": base64.b64encode(classical_pub).decode(),
                "timestamp": int(time.time())
            }

            encrypted_request = self.session.cipher.encrypt(
                json.dumps(rotation_request), include_timestamp=False
            )
            self.send_large_data(self.session.socket, encrypted_request)
            
            self.session.new_key_exchange = new_key_exchange

        except Exception as e:
            print(f"[Quantum Protocol] Key rotation failed: {e}")
            self.disconnect_client()

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

            print(f"[Quantum Protocol] Hybrid key exchange successful")
            print(f"[Quantum Protocol] Shared secret size: {len(shared_secret)} bytes")

            # Create Session
            cipher = EnhancedAESCipher(shared_secret, session_id)
            current_time = time.time()

            self.session = SessionInfo(
                socket=self.client_socket,
                address=self.addr,
                cipher=cipher,
                authenticated=True,
                join_time=current_time,
                last_key_rotation=current_time,
                session_id=session_id,
                certificate=client_cert,
                classical_private_key=self.key_exchange.classical_private_key,
                message_nonces=set()
            )

            # Send confirmation message
            welcome_msg = f"Connection secured successfully | Session ID: {session_id}"
            encrypted_welcome = cipher.encrypt(welcome_msg)
            self.send_large_data(self.client_socket, encrypted_welcome)

        except Exception as e:
            print(f"[Quantum Protocol] Handshake failed for {self.client_id}: {e}")
            self.disconnect_client()
            try:
                self.client_socket.close()
            except:
                pass
            raise

    def handle_key_rotation_response(self, response_json: str):
        if self.session is None:
            return
            
        try:
            response = json.loads(response_json)
            
            if response["type"] == "key_rotation_response" and self.session.new_key_exchange:
                new_kem_ciphertext = base64.b64decode(response["kem_ciphertext"])
                new_client_classical_public = base64.b64decode(response["client_classical_public"])

                new_shared_secret = self.session.new_key_exchange.derive_shared_secret(
                    new_kem_ciphertext, new_client_classical_public
                )

                # Rotate cipher
                self.session.cipher = EnhancedAESCipher(new_shared_secret, self.session.session_id)
                self.session.last_key_rotation = time.time()

                # Clean up temporary state
                self.session.new_key_exchange = None

                print(f"[Quantum Protocol] Key rotation successful for {self.client_id}")

        except Exception as e:
            print(f"[Quantum Protocol] Key rotation error: {e}")
            self.disconnect_client()

    def disconnect_client(self):
        if self.session:
            try:
                self.session.socket.close()
            except:
                pass
            print(f"[Quantum Protocol] Closed connection: {self.client_id}")
            self.session = None

    def cleanup(self):
        if self.key_rotation_timer:
            self.key_rotation_timer.cancel()
            self.key_rotation_timer = None

        self.disconnect_client()
        print("[Quantum Protocol] Server closed")

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
            self.logger.error(f"Quantum Handshake failed: {e}")
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
                  if user_passwd == "680086":
                     encrypted_pass = self.session.cipher.encrypt(as_server.AUTH_PASSED, include_timestamp=False)
                     self.send_large_data(self.session.socket, encrypted_pass)
                     return True
                  else:
                     encrypted_fail = self.session.cipher.encrypt(as_server.AUTH_FAILED, include_timestamp=False)
                     self.send_large_data(self.session.socket, encrypted_fail)
                     return False
           except Exception as e:
                  self.logger.error(f"Password auth failed: {e}")
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
                print(f"[SERVER] {self.client_id} closed connection")
                self.disconnect_client()
                return None

            try:
                decrypted_message, metadata = self.session.cipher.decrypt(data)

                # Check replay protection
                if 'message_id' in metadata:
                    message_id = metadata['message_id']
                    if message_id in self.session.message_nonces:
                        print(f"[SERVER] Replay attack detected from {self.client_id}")
                        return None
                    self.session.message_nonces.add(message_id)

                    if len(self.session.message_nonces) > 1000:
                        self.session.message_nonces.clear()

                # Handle key rotation response
                if decrypted_message.startswith('{"type":"key_rotation_response"'):
                    self.handle_key_rotation_response(decrypted_message)
                    return None

                return decrypted_message
            except ValueError as e:
                print(f"[SERVER] Decryption failed: {e}")
                return None

        except Exception as e:
            print(f"[SERVER] Receive error: {e}")
            self.disconnect_client()
            return None

class ClientManager:
    def __init__(self, logger, client_socket):
        self.logger = logger
        self.client_socket = client_socket
        self.username = 'test'
        
        self.key_exchange = HybridKeyExchange()
        self.sig = Signature(QUANTUM_SIG_ALG)
        self.sig_public_key = self.sig.generate_keypair()

        self.client_cert_key = ec.generate_private_key(CLASSICAL_CURVE)
        self.client_cert = CertificateManager.generate_self_signed_cert(
            f"Quantum Chat Client - {self.username}", self.client_cert_key
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
            chunk = self.client_socket.recv(min(BUFFER_SIZE, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def handle_key_rotation(self, rotation_data: dict):
        try:
            new_key_exchange = HybridKeyExchange()
            client_kem_pub, client_classical_pub = new_key_exchange.get_public_keys()

            server_kem_public = base64.b64decode(rotation_data["kem_public_key"])
            server_classical_public = base64.b64decode(rotation_data["classical_public_key"])

            kem = KeyEncapsulation(QUANTUM_KEM_ALG)
            kem_ciphertext, pq_secret = kem.encap_secret(server_kem_public)

            server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                CLASSICAL_CURVE, server_classical_public
            )
            classical_secret = new_key_exchange.classical_private_key.exchange(
                ec.ECDH(), server_public_key
            )

            combined_secret = pq_secret + classical_secret
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"hybrid_kdf_salt",
                info=b"post_quantum_classical_hybrid",
            )
            new_shared_secret = hkdf.derive(combined_secret)

            rotation_response = {
                "type": "key_rotation_response",
                "kem_ciphertext": base64.b64encode(kem_ciphertext).decode(),
                "client_classical_public": base64.b64encode(client_classical_pub).decode(),
                "timestamp": int(time.time())
            }

            encrypted_response = self.cipher.encrypt(
                json.dumps(rotation_response), include_timestamp=False
            )
            self.send_large_data(encrypted_response)

            self.cipher = EnhancedAESCipher(new_shared_secret, self.session_id)
            self.key_exchange = new_key_exchange

            print("[Quantum Protocol] Key rotation successful")

        except Exception as e:
            print(f"[Quantum Protocol] Key rotation error: {e}")

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
                    print("[Quantum Protocol] Warning: Server certificate verification failed")

            if server_cert:
                fingerprint = get_cert_fingerprint(server_cert)
                trusted_fingerprint_file = ".config/d/trusted_server_fingerprint.txt"
                trusted_fingerprint = None
                if os.path.exists(trusted_fingerprint_file):
                    with open(trusted_fingerprint_file, "r") as f:
                        trusted_fingerprint = f.read().strip()
                if trusted_fingerprint is None:
                    os.makedirs(os.path.dirname(trusted_fingerprint_file), exist_ok=True)
                    with open(trusted_fingerprint_file, "w") as f:
                        f.write(fingerprint)
                    print(f"[Quantum Protocol] Trusted new server cert, fingerprint: {fingerprint}")
                else:
                    if fingerprint != trusted_fingerprint:
                        print(f"[Quantum Protocol] Server cert fingerprint mismatch!")
                        print(f"[Quantum Protocol] Expected: {trusted_fingerprint}")
                        print(f"[Quantum Protocol] Got:      {fingerprint}")
                        raise ValueError("Server certificate verification failed (pin mismatch)")
                    else:
                        print(f"[Quantum Protocol] Server cert fingerprint OK: {fingerprint}")

            print(f"[Quantum Protocol] Established session: {self.session_id}")

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

            self.cipher = EnhancedAESCipher(shared_secret, self.session_id)
            print(f"[Quantum Protocol] Hybrid key exchange successful")

            welcome = self.receive_large_data()
            if welcome:
                try:
                    msg, _ = self.cipher.decrypt(welcome)
                    print(f"[Server] {msg}")
                except:
                    pass

            self.connected = True
        except Exception as e:
            print(f"[Quantum Protocol] Handshake error: {e}")
            self.disconnect()
            raise

    def disconnect(self):
        self.connected = False
        try:
            self.client_socket.close()
        except:
            pass
        print("\n[Quantum Protocol] Disconnected")

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
            print(f"[CLIENT] Send error: {e}")

    def try_handshake(self):
        self.logger.info("Performing quantum handshake...")
        print("If you encounter errors, try running './superconfig.sh'")
        try:
            self.handshake()
            return True
        except Exception as e:
            print(f"[Quantum Protocol] Handshake failed: {e}")
            return False

    def try_auth_passwd(self):
        try:
            data = self.wait_recv_utf8()
            if data and data.startswith(as_server.AUTH_PASSED.decode()):
                return True
                
            user_passwd = input("[AUTH] Enter password > ")
            self.send_message(as_client.PASSWORD.decode() + user_passwd + '\n')
            
            resp = self.wait_recv_utf8()
            if resp and resp.startswith(as_server.AUTH_PASSED.decode()):
                return True
            elif resp and resp.startswith(as_server.AUTH_FAILED.decode()):
                return False
        except Exception as e:
            print(f"Authentication error: {e}")
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
                print("[CLIENT] Server disconnected")
                self.disconnect()
                return None
            try:
                decrypted_message, metadata = self.cipher.decrypt(data, check_timestamp=False)
                '''if decrypted_message.startswith('{"type":"key_rotation"'):
                    rotation_data = json.loads(decrypted_message)
                    if rotation_data["type"] == "key_rotation":
                        self.handle_key_rotation(rotation_data)
                        return None'''

                return decrypted_message
            except ValueError as e:
                print(f"[CLIENT] Decryption failed: {e}")
                return None

        except Exception as e:
            if self.connected:
                print(f"[CLIENT] Receive error: {e}")
            return None
