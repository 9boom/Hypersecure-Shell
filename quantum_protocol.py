"""
FETURES
- Perfect Forward Secrecy (PFS) with Key Rotation
- Certificate-Based Identity Verification
- Enhanced Replay Protection
- Post-Quantum Hybrid Cryptography
- Side-channel Mitigation
- Session Management
"""

import socket
import threading
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

try:
    from oqs import KeyEncapsulation, Signature
except ImportError:
    print("Quantum cryptography not found. Pkease run ./setup py first")
    sys.exit(1)

# Configuration - Post-Quantum Hybrid
QUANTUM_KEM_ALG = "Kyber1024"
QUANTUM_SIG_ALG = "Dilithium3"
CLASSICAL_CURVE = ec.SECP384R1()
KEY_ROTATION_INTERVAL = 300
SESSION_TIMEOUT = 3600
MAX_MESSAGE_AGE = 30

def get_cert_fingerprint(cert: x509.Certificate) -> str:
    # Compute  SHA256 fingerprint of certificate
    return cert.fingerprint(hashes.SHA256()).hex()

@dataclass
class SessionInfo:
    # Session info of client
    socket: socket.socket
    address: tuple
    cipher: 'EnhancedAESCipher'
    authenticated: bool
    join_time: float
    last_key_rotation: float
    session_id: str
    certificate: Optional[x509.Certificate]
    classical_private_key: Optional[ec.EllipticCurvePrivateKey]
    message_nonces: set  # Replay attack protection

class CertificateManager:
    # Manage certificates for identity verification
    @staticmethod
    def generate_self_signed_cert(subject_name: str, private_key) -> x509.Certificate:
        #Build self-signed certificate
        try:
            # Create object
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "TH"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bangkok"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Bangkok"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Quantum Chat"),
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            ])
            
            # Create certificate
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
            print(f"Failed to created certificate: {e}")
            return None
    
    @staticmethod
    def verify_certificate(cert: x509.Certificate, trusted_certs: List[x509.Certificate]) -> bool:
        """Check certificate (simplified version)"""
        try:
            # Check expire
            now = datetime.utcnow()
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False
            return True
        except Exception:
            return False

class EnhancedAESCipher:
    # AES encoder with forward secrecy
    def __init__(self, master_key: bytes, session_id: str):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            from Crypto.Random import get_random_bytes
            self.AES = AES
            self.pad = pad
            self.unpad = unpad
            self.get_random_bytes = get_random_bytes
        except ImportError:
            print("Run pip install pycryptodome first")
            sys.exit(1)
            
        self.master_key = master_key
        self.session_id = session_id
        self.current_key_version = 0
        self.key_history = {}  # Collect old key for decrypt
        self._rotate_keys()
        
    def _derive_key(self, info: bytes, key_version: int = None) -> bytes:
        #HKDF Key Derivation and key versioning
        if key_version is None:
            key_version = self.current_key_version
            
        # Collecting session_id and key_version in derivation
        full_info = info + self.session_id.encode() + key_version.to_bytes(4, 'big')
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"quantum_chat_salt",
            info=full_info,
        )
        return hkdf.derive(self.master_key)
    
    def _rotate_keys(self):
        # Collect old key for short times for decoder coder that stuck before (Sorry for bad eng @_@)
        if self.current_key_version > 0:
            old_enc_key = self._derive_key(b"AES_ENCRYPTION", self.current_key_version - 1)
            old_hmac_key = self._derive_key(b"HMAC_AUTH", self.current_key_version - 1)
            self.key_history[self.current_key_version - 1] = {
                'encryption': old_enc_key,
                'hmac': old_hmac_key,
                'timestamp': time.time()
            }
        
        # Create new key
        self.current_key_version += 1
        self.encryption_key = self._derive_key(b"AES_ENCRYPTION")
        self.hmac_key = self._derive_key(b"HMAC_AUTH")
        
        # Remove old key that older than 5 min
        current_time = time.time()
        expired_versions = [
            v for v, data in self.key_history.items() 
            if current_time - data['timestamp'] > 300
        ]
        for v in expired_versions:
            del self.key_history[v]
    
    def encrypt(self, data: str, include_timestamp: bool = True) -> bytes:
        #Encrypt with timestamp for replay attack protection
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Adding timestamp and nonce for replay protection
        timestamp = int(time.time()).to_bytes(8, 'big')
        nonce = secrets.token_bytes(16)
        message_id = uuid.uuid4().bytes
        
        # Created payload: timestamp + nonce + message_id + data
        if include_timestamp:
            payload = timestamp + nonce + message_id + data
        else:
            payload = data
        
        # use AES-GCM
        cipher = self.AES.new(self.encryption_key, self.AES.MODE_GCM)
        ciphertext, auth_tag = cipher.encrypt_and_digest(payload)
        
        # Collecting : key_version + nonce + auth_tag + ciphertext
        encrypted_data = (
            self.current_key_version.to_bytes(4, 'big') +
            cipher.nonce + auth_tag + ciphertext
        )
        
        # add HMAC
        mac = hmac.new(self.hmac_key, encrypted_data, hashlib.sha256).digest()
        
        return base64.b64encode(mac + encrypted_data)
        
    def decrypt(self, encoded_data: bytes, check_timestamp: bool = True) -> Tuple[str, dict]:
        #Decrypt with timestamp and replay
        data = base64.b64decode(encoded_data)
        
        # separate HMAC
        mac = data[:32]
        encrypted_data = data[32:]
        
        # fetch key version
        key_version = int.from_bytes(encrypted_data[:4], 'big')
        encrypted_data = encrypted_data[4:]
        
        # selecting correct key
        if key_version == self.current_key_version:
            enc_key = self.encryption_key
            hmac_key = self.hmac_key
        elif key_version in self.key_history:
            enc_key = self.key_history[key_version]['encryption']
            hmac_key = self.key_history[key_version]['hmac']
        else:
            raise ValueError(f"Key version {key_version} not found")
        
        # check HMAC
        full_data = key_version.to_bytes(4, 'big') + encrypted_data
        expected_mac = hmac.new(hmac_key, full_data, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification failed")
        
        # separated  nonce, auth_tag, ciphertext
        nonce = encrypted_data[:16]
        auth_tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        # decrypt
        cipher = self.AES.new(enc_key, self.AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, auth_tag)
        
        metadata = {'key_version': key_version}
        
        # check timestamp and replay (if timestamp)
        if check_timestamp and len(decrypted) >= 40:  # 8+16+16 = 40 bytes minimum
            timestamp_bytes = decrypted[:8]
            nonce_bytes = decrypted[8:24]
            message_id = decrypted[24:40]
            actual_data = decrypted[40:]
            
            # check timestamp
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
    #Hybrid Key Exchange: Post-Quantum + Classical
    
    def __init__(self):
        self.kem = KeyEncapsulation(QUANTUM_KEM_ALG)
        self.classical_private_key = ec.generate_private_key(CLASSICAL_CURVE)
        self.kem_public_key = self.kem.generate_keypair()
        
    def get_public_keys(self) -> Tuple[bytes, bytes]:
        #got 2 public keys
        classical_public_bytes = self.classical_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return self.kem_public_key, classical_public_bytes
    
    def derive_shared_secret(self, kem_ciphertext: bytes, peer_classical_public: bytes) -> bytes:
        # Create shared secret format hybrid
        # Post-quantum part
        pq_secret = self.kem.decap_secret(kem_ciphertext)
        
        # Classical ECDH part
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            CLASSICAL_CURVE, peer_classical_public
        )
        classical_secret = self.classical_private_key.exchange(
            ec.ECDH(), peer_public_key
        )
        
        # Combine secrets using HKDF
        combined_secret = pq_secret + classical_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"hybrid_kdf_salt",
            info=b"post_quantum_classical_hybrid",
        )
        
        return hkdf.derive(combined_secret)

class QuantumSecureServer:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients: Dict[str, SessionInfo] = {}
        self.server_cert_manager = server_certificate_manager.ServerCertificateManager()
        
        # Created key exchange and signature objects
        self.key_exchange = HybridKeyExchange()
        self.sig = Signature(QUANTUM_SIG_ALG)
        self.sig_public_key = self.sig.generate_keypair()
        # server certificate
        #self.servejr_cert_key = ec.generate_private_key(CLASSICAL_CURVE)
        #self.server_cert = CertificateManager.generate_self_signed_cert(
        #    "Quantum Chat Server", self.server_cert_key
        #)
        self.server_cert = self.server_cert_manager.init(CLASSICAL_CURVE,CertificateManager)
        # Key rotation timer
        self.key_rotation_timer = None
        self.start_key_rotation_timer()
        
        print(f"[SERVER] Working with Hybrid {QUANTUM_KEM_ALG} + ECDH")
        print(f"[SERVER] Signature Algorithm: {QUANTUM_SIG_ALG}")
        print(f"[SERVER] Key Rotation: every {KEY_ROTATION_INTERVAL} second")
        

    def start_key_rotation_timer(self):
        # Start timer for key rotation
        def rotate_all_keys():
            current_time = time.time()
            disconnected_clients = []
            
            for client_id, session in self.clients.items():
                try:
                    # Rotating key if time too long
                    if current_time - session.last_key_rotation > KEY_ROTATION_INTERVAL:
                        self.initiate_key_rotation(client_id)
                        session.last_key_rotation = current_time
                        
                    # Check session timeout
                    if current_time - session.join_time > SESSION_TIMEOUT:
                        print(f"[SERVER] Session timeout: {client_id}")
                        disconnected_clients.append(client_id)
                        
                except Exception as e:
                    print(f"[SERVER] Failed to key for {client_id}: {e}")
                    disconnected_clients.append(client_id)
            
            # Remove client that expired
            for client_id in disconnected_clients:
                self.disconnect_client(client_id)
            
            # Set new timer
            self.key_rotation_timer = threading.Timer(60, rotate_all_keys)
            self.key_rotation_timer.daemon = True
            self.key_rotation_timer.start()
        
        self.key_rotation_timer = threading.Timer(60, rotate_all_keys)
        self.key_rotation_timer.daemon = True
        self.key_rotation_timer.start()
    
    def initiate_key_rotation(self, client_id: str):
        # Starting process rotating key
        try:
            session = self.clients[client_id]
            
            # Create new key exchange
            new_key_exchange = HybridKeyExchange()
            kem_pub, classical_pub = new_key_exchange.get_public_keys()
            
            # Send cmd key rotation
            rotation_request = {
                "type": "key_rotation",
                "kem_public_key": base64.b64encode(kem_pub).decode(),
                "classical_public_key": base64.b64encode(classical_pub).decode(),
                "timestamp": int(time.time())
            }
            
            # Encrypt with old key
            encrypted_request = session.cipher.encrypt(
                json.dumps(rotation_request), include_timestamp=False
            )
            session.socket.send(encrypted_request)
            
            # Update temp key exchange object
            session.new_key_exchange = new_key_exchange
            
        except Exception as e:
            print(f"[SERVER] Failed to rotation key: {e}")
    
    def start(self):
        # Starting server
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        print(f"[SERVER] Server started at {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                client_id = f"{address[0]}:{address[1]}_{int(time.time())}"
                print(f"[SERVER] New connection: {client_id}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address, client_id)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[SERVER] Closing server...")
        finally:
            self.cleanup()
            
    def send_large_data(self, socket: socket.socket, data: bytes):
        # Send large data with data length
        length = len(data)
        socket.send(struct.pack('!I', length))
        socket.send(data)
    
    def receive_large_data(self, socket: socket.socket) -> bytes:
        # Reading big data so we read data length first
        length_data = b''
        while len(length_data) < 4:
            chunk = socket.recv(4 - len(length_data))
            if not chunk:
                raise ConnectionError("Connection closed while reading length")
            length_data += chunk
        
        length = struct.unpack('!I', length_data)[0]
        
        # Read real data
        data = b''
        while len(data) < length:
            chunk = socket.recv(min(8192, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed while reading data")
            data += chunk
        
        return data

    def handle_client(self, client_socket: socket.socket, address: tuple, client_id: str):
        # Manage client
        try:
            session_id = str(uuid.uuid4())
            
            # 1. Sent  Server Info and Challenge
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
                ).decode() if self.server_cert else None
            }
            
            server_info_data = json.dumps(server_info).encode('utf-8')
            self.send_large_data(client_socket, server_info_data)
            
            # 2. Read Client Response
            response_data = self.receive_large_data(client_socket)
            client_response = json.loads(response_data.decode('utf-8'))
            
            # check certificate (if)
            client_cert = None
            if "certificate" in client_response and client_response["certificate"]:
                cert_data = base64.b64decode(client_response["certificate"])
                client_cert = x509.load_der_x509_certificate(cert_data)
                
                if not CertificateManager.verify_certificate(client_cert, []):
                    raise ValueError("Client certificate verification failed")
            
            # check Digital Signature
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
            
            print(f"[SERVER]  Hybrid key exchange success")
            print(f"[SERVER]  Shared secret size {len(shared_secret)} bytes")
            
            # Create Session
            cipher = EnhancedAESCipher(shared_secret, session_id)
            current_time = time.time()
            
            session = SessionInfo(
                socket=client_socket,
                address=address,
                cipher=cipher,
                authenticated=True,
                join_time=current_time,
                last_key_rotation=current_time,
                session_id=session_id,
                certificate=client_cert,
                classical_private_key=self.key_exchange.classical_private_key,
                message_nonces=set()
            )
            
            self.clients[client_id] = session
            
            # Send comfirm cmd
            welcome_msg = f"Connection secure success | Onlines : {len(self.clients)}"
            encrypted_welcome = cipher.encrypt(welcome_msg)
            client_socket.send(encrypted_welcome)
            
            # Start recv messgae
            self.receive_messages(client_id)
            
        except Exception as e:
            print(f"[SERVER] Failed to manage {client_id}: {e}")
            if client_id in self.clients:
                del self.clients[client_id]
            try:
                client_socket.close()
            except:
                pass
            
    def receive_messages(self, client_id: str):
        # Read and process Enhanced Protection
        session = self.clients[client_id]
        
        while client_id in self.clients:
            try:
                data = session.socket.recv(8192)
                if not data:
                    print(f"[SERVER] {client_id} Close connection")
                    break
                
                # Decrypt
                try:
                    decrypted_message, metadata = session.cipher.decrypt(data)
                    
                    # check replay protection
                    if 'message_id' in metadata:
                        message_id = metadata['message_id']
                        if message_id in session.message_nonces:
                            print(f"[SERVER] Replay attack detected from {client_id}")
                            continue
                        session.message_nonces.add(message_id)
                        
                        # Remove old nonce (save for 5 min)
                        if len(session.message_nonces) > 1000:
                            session.message_nonces.clear()
                    
                    # check key rotation response
                    if decrypted_message.startswith('{"type":"key_rotation_response"'):
                        self.handle_key_rotation_response(client_id, decrypted_message)
                        continue
                    
                    timestamp = time.strftime("%H:%M:%S")
                    formatted_message = f"[{timestamp}] {client_id}: {decrypted_message}"
                    
                    print(formatted_message)
                    self.broadcast_message(formatted_message, exclude_client=client_id)
                    
                except ValueError as e:
                    print(f"[SERVER] Failed to decrypt: {e}")
                    continue
                    
            except Exception as e:
                print(f"[SERVER] Failed to reading {client_id}: {e}")
                break
                
        self.disconnect_client(client_id)
        
    def handle_key_rotation_response(self, client_id: str, response_json: str):
        #manage response from key rotation
        try:
            response = json.loads(response_json)
            session = self.clients[client_id]
            
            if response["type"] == "key_rotation_response" and hasattr(session, 'new_key_exchange'):
                # got new ciphertext
                new_kem_ciphertext = base64.b64decode(response["kem_ciphertext"])
                new_client_classical_public = base64.b64decode(response["client_classical_public"])
                
                # Create new shared secret
                new_shared_secret = session.new_key_exchange.derive_shared_secret(
                    new_kem_ciphertext, new_client_classical_public
                )
                
                # rotating cipher
                session.cipher = EnhancedAESCipher(new_shared_secret, session.session_id)
                session.last_key_rotation = time.time()
                
                # rm temporary key exchange
                delattr(session, 'new_key_exchange')
                
                print(f"[SERVER] Key rotation success for {client_id}")
                
        except Exception as e:
            print(f"[SERVER] Error in key rotation: {e}")
    
    def broadcast_message(self, message: str, exclude_client: Optional[str] = None):
        #สSend all cmd to all clients
        disconnected_clients = []
        
        for client_id, session in self.clients.items():
            if client_id == exclude_client:
                continue
                
            try:
                encrypted_message = session.cipher.encrypt(message)
                session.socket.send(encrypted_message)
            except Exception as e:
                print(f"[SERVER] Cannot sent to {client_id}: {e}")
                disconnected_clients.append(client_id)
        
        # Romoveing client that disconnected
        for client_id in disconnected_clients:
            self.disconnect_client(client_id)
    
    def disconnect_client(self, client_id: str):
        #Disconnected and cleaned
        if client_id in self.clients:
            try:
                self.clients[client_id].socket.close()
            except:
                pass
            del self.clients[client_id]
            print(f"[SERVER] Closed connected {client_id}")
    
    def cleanup(self):
        # Clean res
        if self.key_rotation_timer:
            self.key_rotation_timer.cancel()
            
        for client_id in list(self.clients.keys()):
            self.disconnect_client(client_id)
            
        try:
            self.server_socket.close()
        except:
            pass
        print("[SERVER] Closing server...")


class QuantumSecureClient:
    def __init__(self, host='localhost', port=9000, username="Anonymous"):
        self.host = host
        self.port = port
        self.username = username
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Created key exchange and signature objects
        self.key_exchange = HybridKeyExchange()
        self.sig = Signature(QUANTUM_SIG_ALG)
        self.sig_public_key = self.sig.generate_keypair()
        
        # Created client certificate
        self.client_cert_key = ec.generate_private_key(CLASSICAL_CURVE)
        self.client_cert = CertificateManager.generate_self_signed_cert(
            f"Quantum Chat Client - {username}", self.client_cert_key
        )
        
        self.cipher = None
        self.connected = False
        self.session_id = None
        
    def send_large_data(self, socket: socket.socket, data: bytes):
        # Send large data with data length
        length = len(data)
        socket.send(struct.pack('!I', length))
        socket.send(data)
    
    def receive_large_data(self, socket: socket.socket) -> bytes:
        # Reading large data and read length first
        length_data = b''
        while len(length_data) < 4:
            chunk = socket.recv(4 - len(length_data))
            if not chunk:
                raise ConnectionError("Connection closed while reading length")
            length_data += chunk
        
        length = struct.unpack('!I', length_data)[0]
        
        # Read real data
        data = b''
        while len(data) < length:
            chunk = socket.recv(min(8192, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed while reading data")
            data += chunk
        
        return data

    def connect(self):
        try:
            self.client_socket.connect((self.host, self.port))
            print(f"[CLIENT] Connected to {self.host}:{self.port}")
            
            # Read server info
            server_data = self.receive_large_data(self.client_socket)
            server_info = json.loads(server_data.decode('utf-8'))
            
            self.session_id = server_info["session_id"]
            server_kem_public = base64.b64decode(server_info["kem_public_key"])
            server_classical_public = base64.b64decode(server_info["classical_public_key"])
            server_sig_public = base64.b64decode(server_info["sig_public_key"])
            server_challenge = base64.b64decode(server_info["server_challenge"])
            
            # check server certificate (if have)
            if server_info.get("certificate"):
                cert_data = base64.b64decode(server_info["certificate"])
                server_cert = x509.load_der_x509_certificate(cert_data)
                if not CertificateManager.verify_certificate(server_cert, []):
                    print("[CLIENT] Warning: Cannot check server certificate")

            # === PIN SERVER CERT ===
            fingerprint = get_cert_fingerprint(server_cert)
            trusted_fingerprint_file = "../.config/d/trusted_server_fingerprint.txt"
            trusted_fingerprint = None
            if os.path.exists(trusted_fingerprint_file):
               with open(trusted_fingerprint_file, "r") as f:
                    trusted_fingerprint = f.read().strip()
            if trusted_fingerprint is None:
               # First time trust and Save fingerprint
               with open(trusted_fingerprint_file, "w") as f:
                    f.write(fingerprint)
               print(f"[CLIENT] First time trust server cert, saved fingerprint: {fingerprint}")
            else:
                if fingerprint != trusted_fingerprint:
                    print(f"[CLIENT] ❌ Server cert fingerprint mismatch!")
                    print(f"[CLIENT] Expected: {trusted_fingerprint}")
                    print(f"[CLIENT] Got:      {fingerprint}")
                    raise ValueError("Server certificate verification failed (pin mismatch)")
                else:
                    print(f"[CLIENT] 🔐 Server cert fingerprint OK: {fingerprint}")
            
            print(f"[CLIENT] Got server info for session: {self.session_id}")
            
            # Create hybrid key exchange
            client_kem_pub, client_classical_pub = self.key_exchange.get_public_keys()
            
            # Key encapsulation for server
            kem_ciphertext, pq_secret = KeyEncapsulation(QUANTUM_KEM_ALG).encap_secret(server_kem_public)
            
            # ECDH exchange
            server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                CLASSICAL_CURVE, server_classical_public
            )
            classical_secret = self.key_exchange.classical_private_key.exchange(
                ec.ECDH(), server_public_key
            )
            
            # Combine secrets
            combined_secret = pq_secret + classical_secret
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"hybrid_kdf_salt",
                info=b"post_quantum_classical_hybrid",
            )
            shared_secret = hkdf.derive(combined_secret)
            
            # Build amd sign challenge response
            challenge_response = server_challenge + b"client_response_" + self.session_id.encode()
            signature = self.sig.sign(challenge_response)
            
            # preparing client response
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
            self.send_large_data(self.client_socket, client_response_data)
            
            # Build cipher
            self.cipher = EnhancedAESCipher(shared_secret, self.session_id)
            print(f"[CLIENT] Hybrid key exchange success")
            
            # Got comfirnm
            welcome_data = self.client_socket.recv(4096)
            welcome_message, _ = self.cipher.decrypt(welcome_data)
            print(f"[CLIENT] {welcome_message}")
            
            self.connected = True
            
            # Thread for recv
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Send message
            self.send_messages()
            
        except Exception as e:
            print(f"[CLIENT] Error: {e}")
            self.disconnect()
            
    def handle_key_rotation(self, rotation_data: dict):
        #Manage key rotayion from server
        try:
            # Create new key exchange
            new_key_exchange = HybridKeyExchange()
            client_kem_pub, client_classical_pub = new_key_exchange.get_public_keys()
            
            # new Key encapsulation
            server_kem_public = base64.b64decode(rotation_data["kem_public_key"])
            server_classical_public = base64.b64decode(rotation_data["classical_public_key"])
            
            kem_ciphertext, pq_secret = KeyEncapsulation(QUANTUM_KEM_ALG).encap_secret(server_kem_public)
            
            # new ECDH exchange
            server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                CLASSICAL_CURVE, server_classical_public
            )
            classical_secret = new_key_exchange.classical_private_key.exchange(
                ec.ECDH(), server_public_key
            )
            
            # new Combine secrets
            combined_secret = pq_secret + classical_secret
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"hybrid_kdf_salt",
                info=b"post_quantum_classical_hybrid",
            )
            new_shared_secret = hkdf.derive(combined_secret)
            
            # send respound back
            rotation_response = {
                "type": "key_rotation_response",
                "kem_ciphertext": base64.b64encode(kem_ciphertext).decode(),
                "client_classical_public": base64.b64encode(client_classical_pub).decode(),
                "timestamp": int(time.time())
            }
            
            # send with old key
            encrypted_response = self.cipher.encrypt(
                json.dumps(rotation_response), include_timestamp=False
            )
            self.client_socket.send(encrypted_response)
            
            # Update cipher
            self.cipher = EnhancedAESCipher(new_shared_secret, self.session_id)
            self.key_exchange = new_key_exchange
            
            print("[CLIENT] Key rotation success")
            
        except Exception as e:
            print(f"[CLIENT] Error in key rotation: {e}")
            
    def receive_messages(self):
        while self.connected:
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    print("[CLIENT] Server has been disconnected")
                    break
                    
                try:
                    decrypted_message, metadata = self.cipher.decrypt(data, check_timestamp=False)
                    
                    # check is its key rotation req ???
                    if decrypted_message.startswith('{"type":"key_rotation"'):
                        rotation_data = json.loads(decrypted_message)
                        if rotation_data["type"] == "key_rotation":
                            self.handle_key_rotation(rotation_data)
                            continue
                    
                    print(f"\n{decrypted_message}")
                    print(f"[{self.username}] >>> ", end="", flush=True)
                    
                except ValueError as e:
                    print(f"[CLIENT] Error to decrypt: {e}")
                    continue
                    
            except Exception as e:
                if self.connected:
                    print(f"[CLIENT] Error to recvier: {e}")
                break
                
        self.disconnect()
        
    def send_messages(self):        
        try:
            while self.connected:
                message = input(f"[{self.username}] >>> ")
                
                if message.lower() in ['/quit', 'exit']:
                    break
                    
                if message.strip():
                    encrypted_message = self.cipher.encrypt(message)
                    self.client_socket.send(encrypted_message)
                    
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"[CLIENT] Error: {e}")
            
        self.disconnect()
        
    def disconnect(self):
        self.connected = False
        try:
            self.client_socket.close()
        except:
            pass
        print("\n[CLIENT] Disconnected")
