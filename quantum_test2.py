"""
ระบบการสื่อสารควอนตัมปลอดภัยขั้นสูง
ปรับปรุงความปลอดภัยและประสิทธิภาพจากโค้ดต้นฉบับ
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
from typing import Dict, Optional, Tuple

# ติดตั้ง dependencies:
# pip install liboqs pycryptodome

try:
    from oqs import KeyEncapsulation, Signature
except ImportError:
    print("กรุณาติดตั้ง liboqs-python ก่อน: pip install liboqs")
    sys.exit(1)

# ใช้อัลกอริทึมที่แข็งแกร่งที่สุด
QUANTUM_KEM_ALG = "Kyber1024"  # ปรับเป็น Kyber1024 สำหรับความปลอดภัยสูงสุด
QUANTUM_SIG_ALG = "Dilithium3"  # เพิ่ม Digital Signature สำหรับ Authentication

class EnhancedAESCipher:
    """คลาสการเข้ารหัส AES ที่ปรับปรุงแล้ว"""
    
    def __init__(self, key: bytes):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            from Crypto.Random import get_random_bytes
            self.AES = AES
            self.pad = pad
            self.unpad = unpad
            self.get_random_bytes = get_random_bytes
        except ImportError:
            print("กรุณาติดตั้ง pycryptodome ก่อน: pip install pycryptodome")
            sys.exit(1)
            
        # ใช้ HKDF สำหรับ Key Derivation
        self.master_key = key
        self.encryption_key = self._derive_key(b"AES_ENCRYPTION")
        self.hmac_key = self._derive_key(b"HMAC_AUTH")
        
    def _derive_key(self, info: bytes) -> bytes:
        """HKDF Key Derivation สำหรับแยกกุญแจ"""
        return hashlib.pbkdf2_hmac('sha256', self.master_key, info, 100000, 32)
    
    def encrypt(self, data: str) -> bytes:
        """เข้ารหัสด้วย AES-256-GCM (Authenticated Encryption)"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # ใช้ AES-GCM แทน CBC เพื่อ Authenticated Encryption
        cipher = self.AES.new(self.encryption_key, self.AES.MODE_GCM)
        ciphertext, auth_tag = cipher.encrypt_and_digest(data)
        
        # รวม nonce + auth_tag + ciphertext
        encrypted_data = cipher.nonce + auth_tag + ciphertext
        
        # เพิ่ม HMAC สำหรับ Additional Authentication
        mac = hmac.new(self.hmac_key, encrypted_data, hashlib.sha256).digest()
        
        return base64.b64encode(mac + encrypted_data)
        
    def decrypt(self, encoded_data: bytes) -> str:
        """ถอดรหัส AES-256-GCM"""
        data = base64.b64decode(encoded_data)
        
        # แยก HMAC และตรวจสอบ
        mac = data[:32]  # SHA256 = 32 bytes
        encrypted_data = data[32:]
        
        # ตรวจสอบ HMAC
        expected_mac = hmac.new(self.hmac_key, encrypted_data, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification failed - ข้อมูลอาจถูกแก้ไข")
        
        # แยก nonce, auth_tag, ciphertext
        nonce = encrypted_data[:16]  # GCM nonce = 16 bytes
        auth_tag = encrypted_data[16:32]  # GCM tag = 16 bytes
        ciphertext = encrypted_data[32:]
        
        # ถอดรหัส
        cipher = self.AES.new(self.encryption_key, self.AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, auth_tag)
        
        return decrypted.decode('utf-8')


class QuantumSecureServer:
    """เซิร์ฟเวอร์ที่มีความปลอดภัยขั้นสูง"""
    
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients: Dict[str, dict] = {}
        
        # สร้างคู่กุญแจ KEM และ Digital Signature
        self.kem = KeyEncapsulation(QUANTUM_KEM_ALG)
        self.sig = Signature(QUANTUM_SIG_ALG)
        
        self.kem_public_key = self.kem.generate_keypair()
        self.sig_public_key = self.sig.generate_keypair()
        
        print(f"[SERVER] เริ่มการทำงานด้วย {QUANTUM_KEM_ALG} + {QUANTUM_SIG_ALG}")
        print(f"[SERVER] KEM Public Key ขนาด: {len(self.kem_public_key)} bytes")
        print(f"[SERVER] Signature Public Key ขนาด: {len(self.sig_public_key)} bytes")
        
    def start(self):
        """เริ่มการทำงานของเซิร์ฟเวอร์"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        print(f"[SERVER] เริ่มทำงานที่ {self.host}:{self.port}")
        
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                client_id = f"{address[0]}:{address[1]}"
                print(f"[SERVER] การเชื่อมต่อใหม่: {client_id}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address, client_id)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[SERVER] ข้อผิดพลาด: {e}")
                
        self.cleanup()
        
    def send_large_data(self, socket: socket.socket, data: bytes):
        """ส่งข้อมูลขนาดใหญ่พร้อมระบุความยาว"""
        # ส่งความยาวข้อมูลก่อน (4 bytes)
        length = len(data)
        socket.send(length.to_bytes(4, byteorder='big'))
        # ส่งข้อมูลจริง
        socket.send(data)
    
    def receive_large_data(self, socket: socket.socket) -> bytes:
        """รับข้อมูลขนาดใหญ่โดยอ่านความยาวก่อน"""
        # รับความยาวข้อมูล (4 bytes)
        length_data = b''
        while len(length_data) < 4:
            chunk = socket.recv(4 - len(length_data))
            if not chunk:
                raise ConnectionError("Connection closed while reading length")
            length_data += chunk
        
        length = int.from_bytes(length_data, byteorder='big')
        
        # รับข้อมูลจริงตามความยาวที่ระบุ
        data = b''
        while len(data) < length:
            chunk = socket.recv(min(8192, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed while reading data")
            data += chunk
        
        return data

    def handle_client(self, client_socket: socket.socket, address: tuple, client_id: str):
        """จัดการ client พร้อมการตรวจสอบตัวตน"""
        try:
            # ขั้นตอนที่ 1: ส่ง Public Keys
            key_package = {
                "kem_public_key": base64.b64encode(self.kem_public_key).decode(),
                "sig_public_key": base64.b64encode(self.sig_public_key).decode(),
                "server_challenge": base64.b64encode(secrets.token_bytes(32)).decode()
            }
            
            key_package_data = json.dumps(key_package).encode('utf-8')
            self.send_large_data(client_socket, key_package_data)
            print(f"[SERVER] ส่ง key package ไปยัง {client_id} (ขนาด: {len(key_package_data)} bytes)")
            
            # ขั้นตอนที่ 2: รับ KEM Ciphertext และ Client Response
            response_data = self.receive_large_data(client_socket)
            client_response = json.loads(response_data.decode('utf-8'))
            
            # ตรวจสอบ Digital Signature
            challenge_response = base64.b64decode(client_response["challenge_response"])
            signature = base64.b64decode(client_response["signature"])
            client_sig_public_key = base64.b64decode(client_response["client_sig_public_key"])
            
            # ตรวจสอบลายเซ็น (ในระบบจริงต้องตรวจสอบ Certificate)
            client_sig = Signature(QUANTUM_SIG_ALG)
            if not client_sig.verify(challenge_response, signature, client_sig_public_key):
                raise ValueError("Client signature verification failed")
            
            # ขั้นตอนที่ 3: Key Exchange
            ciphertext = base64.b64decode(client_response["ciphertext"])
            shared_secret = self.kem.decap_secret(ciphertext)
            
            print(f"[SERVER] ✓ ตรวจสอบลายเซ็นสำเร็จ")
            print(f"[SERVER] ✓ สร้าง shared secret ขนาด {len(shared_secret)} bytes")
            
            # สร้าง Cipher และเก็บข้อมูล Client
            cipher = EnhancedAESCipher(shared_secret)
            self.clients[client_id] = {
                "socket": client_socket,
                "address": address,
                "cipher": cipher,
                "authenticated": True,
                "join_time": time.time()
            }
            
            # ส่งข้อความยืนยันการเชื่อมต่อ
            welcome_msg = f"เชื่อมต่อปลอดภัยสำเร็จ! ผู้ใช้ออนไลน์: {len(self.clients)} คน"
            encrypted_welcome = cipher.encrypt(welcome_msg)
            client_socket.send(encrypted_welcome)
            
            # เริ่มรับข้อความ
            self.receive_messages(client_id)
            
        except Exception as e:
            print(f"[SERVER] ข้อผิดพลาดในการจัดการ {client_id}: {e}")
            if client_id in self.clients:
                del self.clients[client_id]
            client_socket.close()
            
    def receive_messages(self, client_id: str):
        """รับและประมวลผลข้อความ"""
        client_info = self.clients[client_id]
        client_socket = client_info["socket"]
        cipher = client_info["cipher"]
        
        while client_id in self.clients:
            try:
                data = client_socket.recv(8192)
                if not data:
                    print(f"[SERVER] {client_id} ตัดการเชื่อมต่อ")
                    break
                
                # ถอดรหัสข้อความ
                decrypted_message = cipher.decrypt(data)
                timestamp = time.strftime("%H:%M:%S")
                formatted_message = f"[{timestamp}] {client_id}: {decrypted_message}"
                
                print(formatted_message)
                
                # กระจายข้อความไปยัง client อื่น
                self.broadcast_message(formatted_message, exclude_client=client_id)
                
            except Exception as e:
                print(f"[SERVER] ข้อผิดพลาดในการรับข้อความจาก {client_id}: {e}")
                break
                
        # ทำความสะอาดเมื่อ client ออก
        if client_id in self.clients:
            del self.clients[client_id]
        client_socket.close()
        print(f"[SERVER] ปิดการเชื่อมต่อ {client_id}")
        
    def broadcast_message(self, message: str, exclude_client: Optional[str] = None):
        """ส่งข้อความไปยัง client ทั้งหมด"""
        disconnected_clients = []
        
        for client_id, client_info in self.clients.items():
            if client_id == exclude_client:
                continue
                
            try:
                encrypted_message = client_info["cipher"].encrypt(message)
                client_info["socket"].send(encrypted_message)
            except Exception as e:
                print(f"[SERVER] ไม่สามารถส่งข้อความถึง {client_id}: {e}")
                disconnected_clients.append(client_id)
        
        # ลบ client ที่ตัดการเชื่อมต่อ
        for client_id in disconnected_clients:
            if client_id in self.clients:
                self.clients[client_id]["socket"].close()
                del self.clients[client_id]
    
    def cleanup(self):
        """ทำความสะอาดทรัพยากร"""
        for client_info in self.clients.values():
            client_info["socket"].close()
        self.server_socket.close()
        print("[SERVER] ปิดเซิร์ฟเวอร์...")


class QuantumSecureClient:
    """ไคลเอนต์ที่มีความปลอดภัยขั้นสูง"""
    
    def __init__(self, host='localhost', port=9000, username="Anonymous"):
        self.host = host
        self.port = port
        self.username = username
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # สร้างคู่กุญแจสำหรับ client
        self.kem = KeyEncapsulation(QUANTUM_KEM_ALG)
        self.sig = Signature(QUANTUM_SIG_ALG)
        self.sig_public_key = self.sig.generate_keypair()
        
        self.cipher = None
        self.connected = False
        
    def send_large_data(self, socket: socket.socket, data: bytes):
        """ส่งข้อมูลขนาดใหญ่พร้อมระบุความยาว"""
        # ส่งความยาวข้อมูลก่อน (4 bytes)
        length = len(data)
        socket.send(length.to_bytes(4, byteorder='big'))
        # ส่งข้อมูลจริง
        socket.send(data)
    
    def receive_large_data(self, socket: socket.socket) -> bytes:
        """รับข้อมูลขนาดใหญ่โดยอ่านความยาวก่อน"""
        # รับความยาวข้อมูล (4 bytes)
        length_data = b''
        while len(length_data) < 4:
            chunk = socket.recv(4 - len(length_data))
            if not chunk:
                raise ConnectionError("Connection closed while reading length")
            length_data += chunk
        
        length = int.from_bytes(length_data, byteorder='big')
        
        # รับข้อมูลจริงตามความยาวที่ระบุ
        data = b''
        while len(data) < length:
            chunk = socket.recv(min(8192, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed while reading data")
            data += chunk
        
        return data

    def connect(self):
        """เชื่อมต่อแบบปลอดภัยกับเซิร์ฟเวอร์"""
        try:
            # เชื่อมต่อ
            self.client_socket.connect((self.host, self.port))
            print(f"[CLIENT] เชื่อมต่อกับ {self.host}:{self.port}")
            
            # รับ key package จากเซิร์ฟเวอร์
            key_data = self.receive_large_data(self.client_socket)
            key_package = json.loads(key_data.decode('utf-8'))
            
            server_kem_public_key = base64.b64decode(key_package["kem_public_key"])
            server_sig_public_key = base64.b64decode(key_package["sig_public_key"])
            server_challenge = base64.b64decode(key_package["server_challenge"])
            
            print(f"[CLIENT] ได้รับ key package จากเซิร์ฟเวอร์")
            
            # สร้าง shared secret
            ciphertext, shared_secret = self.kem.encap_secret(server_kem_public_key)
            
            # เซ็นต์ challenge เพื่อยืนยันตัวตน
            challenge_response = server_challenge + b"client_response"
            signature = self.sig.sign(challenge_response)
            
            # ส่งข้อมูลกลับไปยังเซิร์ฟเวอร์
            client_response = {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "challenge_response": base64.b64encode(challenge_response).decode(),
                "signature": base64.b64encode(signature).decode(),
                "client_sig_public_key": base64.b64encode(self.sig_public_key).decode()
            }
            
            client_response_data = json.dumps(client_response).encode('utf-8')
            self.send_large_data(self.client_socket, client_response_data)
            print(f"[CLIENT] ส่งข้อมูลการยืนยันตัวตน (ขนาด: {len(client_response_data)} bytes)")
            
            # สร้าง Cipher
            self.cipher = EnhancedAESCipher(shared_secret)
            print(f"[CLIENT] ✓ สร้าง shared secret ขนาด {len(shared_secret)} bytes")
            
            # รับข้อความยืนยันแบบ binary
            welcome_data = self.client_socket.recv(4096)
            welcome_message = self.cipher.decrypt(welcome_data)
            print(f"[CLIENT] {welcome_message}")
            
            self.connected = True
            
            # เริ่ม thread สำหรับรับข้อความ
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # เริ่มส่งข้อความ
            self.send_messages()
            
        except Exception as e:
            print(f"[CLIENT] ข้อผิดพลาด: {e}")
            self.disconnect()
            
    def receive_messages(self):
        """รับข้อความจากเซิร์ฟเวอร์"""
        while self.connected:
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    print("[CLIENT] เซิร์ฟเวอร์ตัดการเชื่อมต่อ")
                    break
                    
                decrypted_message = self.cipher.decrypt(data)
                print(f"\n📩 {decrypted_message}")
                print(f"[{self.username}] >>> ", end="", flush=True)
                
            except Exception as e:
                if self.connected:
                    print(f"[CLIENT] ข้อผิดพลาดในการรับข้อความ: {e}")
                break
                
        self.disconnect()
        
    def send_messages(self):
        """ส่งข้อความไปยังเซิร์ฟเวอร์"""
        print(f"\n🔐 เชื่อมต่อปลอดภัยแล้ว! พิมพ์ข้อความ (พิมพ์ '/quit' เพื่อออก)")
        print("=" * 50)
        
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
            print(f"[CLIENT] ข้อผิดพลาด: {e}")
            
        self.disconnect()
        
    def disconnect(self):
        """ตัดการเชื่อมต่อ"""
        self.connected = False
        self.client_socket.close()
        print("\n[CLIENT] ตัดการเชื่อมต่อแล้ว")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="ระบบแชทเข้ารหัสควอนตัมขั้นสูง")
    parser.add_argument("mode", choices=["server", "client"], 
                       help="โหมด: server หรือ client")
    parser.add_argument("--host", default="localhost", 
                       help="ที่อยู่เซิร์ฟเวอร์")
    parser.add_argument("--port", type=int, default=9000, 
                       help="พอร์ต")
    parser.add_argument("--username", default="Anonymous", 
                       help="ชื่อผู้ใช้ (สำหรับ client)")
    
    args = parser.parse_args()
    
    print("🔐 ระบบแชทเข้ารหัสควอนตัมขั้นสูง")
    print(f"📡 Algorithm: {QUANTUM_KEM_ALG} + {QUANTUM_SIG_ALG}")
    print("=" * 50)
    
    if args.mode == "server":
        server = QuantumSecureServer(args.host, args.port)
        try:
            server.start()
        except KeyboardInterrupt:
            server.cleanup()
            
    elif args.mode == "client":
        client = QuantumSecureClient(args.host, args.port, args.username)
        client.connect()


if __name__ == "__main__":
    main()
