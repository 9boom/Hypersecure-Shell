"""
ระบบการสื่อสารควอนตัมปลอดภัยด้วย liboqs Python
ใช้อัลกอริทึม CRYSTALS-Kyber (ชนะการประกวด NIST PQC)
"""

import socket
import threading
import json
import os
import sys
import time
import base64

# ติดตั้ง liboqs-python ก่อนใช้งาน:
# pip install liboqs

try:
    from oqs import KeyEncapsulation
except ImportError:
    print("กรุณาติดตั้ง liboqs-python ก่อน: pip install liboqs")
    sys.exit(1)

# เลือกใช้ CRYSTALS-Kyber เนื่องจากเป็นอัลกอริทึม PQC มาตรฐานที่ NIST รับรอง
# และเป็นที่ยอมรับว่ามีความปลอดภัยสูงในการต้านทานการโจมตีจากควอนตัมคอมพิวเตอร์
QUANTUM_ALG = "Kyber768"

class AESCipher:
    """คลาสสำหรับการเข้ารหัสและถอดรหัสด้วย AES ใช้ key จาก Kyber KEM"""
    
    def __init__(self, key):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            self.AES = AES
            self.pad = pad
            self.unpad = unpad
        except ImportError:
            print("กรุณาติดตั้ง pycryptodome ก่อน: pip install pycryptodome")
            sys.exit(1)
            
        # ใช้ key ขนาด 32 ไบต์สำหรับ AES-256
        self.key = key[:32]
        
    def encrypt(self, data):
        """เข้ารหัสข้อมูลด้วย AES-256-CBC"""
        iv = os.urandom(16)  # Initialization vector ควรสุ่มและไม่ซ้ำ
        cipher = self.AES.new(self.key, self.AES.MODE_CBC, iv)
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Padding ข้อมูลให้ได้ขนาดเป็นทวีคูณของ block size
        encrypted = cipher.encrypt(self.pad(data, self.AES.block_size))
        
        # ส่งคืน iv + ciphertext เพื่อใช้ในการถอดรหัส
        return base64.b64encode(iv + encrypted)
        
    def decrypt(self, encoded_data):
        """ถอดรหัสข้อมูล AES-256-CBC"""
        data = base64.b64decode(encoded_data)
        
        # แยก IV ออกจากข้อมูลที่เข้ารหัสแล้ว
        iv = data[:16]
        encrypted = data[16:]
        
        cipher = self.AES.new(self.key, self.AES.MODE_CBC, iv)
        decrypted = self.unpad(cipher.decrypt(encrypted), self.AES.block_size)
        
        return decrypted.decode('utf-8')


class QuantumServer:
    """เซิร์ฟเวอร์ที่ใช้การเข้ารหัสควอนตัม"""
    
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = []
        
        # สร้างคู่กุญแจ Kyber
        self.kem = KeyEncapsulation(QUANTUM_ALG)
        self.public_key = self.kem.generate_keypair()
        print(f"[SERVER] เริ่มการทำงานโดยใช้อัลกอริทึม {QUANTUM_ALG}")
        
    def start(self):
        """เริ่มการทำงานของเซิร์ฟเวอร์"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[SERVER] เริ่มทำงานที่ {self.host}:{self.port}")
        
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"[SERVER] มีการเชื่อมต่อใหม่จาก {address}")
                
                # สร้าง thread ใหม่สำหรับการจัดการลูกค้าแต่ละราย
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[SERVER] เกิดข้อผิดพลาด: {e}")
                
        self.server_socket.close()
        
    def handle_client(self, client_socket, address):
        """จัดการการเชื่อมต่อกับ client รายใหม่"""
        try:
            # ส่ง public key ไปยัง client
            client_socket.send(self.public_key)
            print(f"[SERVER] ส่ง public key ไปยัง {address}")
            
            # รับ ciphertext และ shared secret
            ciphertext = client_socket.recv(2048)
            print(f"[SERVER] ได้รับ ciphertext จาก {address}")
            
            # ถอดรหัส shared secret ด้วย private key
            shared_secret = self.kem.decap_secret(ciphertext)
            print(f"[SERVER] สร้าง shared secret สำเร็จ บัฟเฟอร์ขนาด {len(shared_secret)} ไบต์")
            
            # สร้างกลไกเข้ารหัส AES ด้วย shared secret
            cipher = AESCipher(shared_secret)
            
            # เพิ่ม client ใหม่เข้าไปในรายการ
            client_info = {
                "socket": client_socket,
                "address": address,
                "cipher": cipher
            }
            self.clients.append(client_info)
            
            # รับข้อความจาก client
            self.receive_messages(client_info)
            
        except Exception as e:
            print(f"[SERVER] เกิดข้อผิดพลาดในการจัดการ client {address}: {e}")
            client_socket.close()
            
    def receive_messages(self, client_info):
        """รับและถอดรหัสข้อความจาก client"""
        client_socket = client_info["socket"]
        cipher = client_info["cipher"]
        address = client_info["address"]
        
        while True:
            try:
                # รับข้อความที่เข้ารหัสแล้ว
                data = client_socket.recv(4096)
                if not data:
                    print(f"[SERVER] {address} ตัดการเชื่อมต่อ")
                    break
                    
                # ถอดรหัสข้อความ
                decrypted_message = cipher.decrypt(data)
                print(f"[{address}] {decrypted_message}")
                
                # กระจายข้อความไปยัง client อื่นๆ
                for other_client in self.clients:
                    if other_client["socket"] != client_socket:
                        encrypted_message = other_client["cipher"].encrypt(
                            f"[{address[0]}:{address[1]}] {decrypted_message}"
                        )
                        other_client["socket"].send(encrypted_message)
                        
            except Exception as e:
                print(f"[SERVER] เกิดข้อผิดพลาดในการรับข้อความจาก {address}: {e}")
                break
                
        # ลบ client ออกจากรายการและปิดการเชื่อมต่อ
        self.clients.remove(client_info)
        client_socket.close()
        
    def broadcast(self, message):
        """ส่งข้อความไปยัง client ทั้งหมด"""
        for client in self.clients:
            try:
                encrypted_message = client["cipher"].encrypt(message)
                client["socket"].send(encrypted_message)
            except Exception as e:
                print(f"[SERVER] ไม่สามารถส่งข้อความถึง {client['address']}: {e}")


class QuantumClient:
    """ไคลเอนต์ที่ใช้การเข้ารหัสควอนตัม"""
    
    def __init__(self, host='localhost', port=9000, username="Client"):
        self.host = host
        self.port = port
        self.username = username
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.kem = KeyEncapsulation(QUANTUM_ALG)
        self.cipher = None
        
    def connect(self):
        """เชื่อมต่อกับเซิร์ฟเวอร์และแลกเปลี่ยนกุญแจ"""
        try:
            # เชื่อมต่อกับเซิร์ฟเวอร์
            self.client_socket.connect((self.host, self.port))
            print(f"[CLIENT] เชื่อมต่อกับเซิร์ฟเวอร์ {self.host}:{self.port} สำเร็จ")
            
            # รับ public key ของเซิร์ฟเวอร์
            server_public_key = self.client_socket.recv(2048)
            print(f"[CLIENT] ได้รับ public key จากเซิร์ฟเวอร์")
            
            # สร้าง shared secret และ ciphertext
            ciphertext, shared_secret = self.kem.encap_secret(server_public_key)
            print(f"[CLIENT] สร้าง shared secret สำเร็จ บัฟเฟอร์ขนาด {len(shared_secret)} ไบต์")
            
            # ส่ง ciphertext ไปยังเซิร์ฟเวอร์
            self.client_socket.send(ciphertext)
            print("[CLIENT] ส่ง ciphertext ไปยังเซิร์ฟเวอร์")
            
            # สร้างกลไกเข้ารหัส AES ด้วย shared secret
            self.cipher = AESCipher(shared_secret)
            
            # เริ่มรับข้อความ
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # เริ่มการส่งข้อความ
            self.send_messages()
            
        except Exception as e:
            print(f"[CLIENT] เกิดข้อผิดพลาดในการเชื่อมต่อ: {e}")
            self.client_socket.close()
            
    def receive_messages(self):
        """รับและถอดรหัสข้อความจากเซิร์ฟเวอร์"""
        while True:
            try:
                # รับข้อความที่เข้ารหัสแล้ว
                data = self.client_socket.recv(4096)
                if not data:
                    print("[CLIENT] เซิร์ฟเวอร์ตัดการเชื่อมต่อ")
                    break
                    
                # ถอดรหัสข้อความ
                decrypted_message = self.cipher.decrypt(data)
                print(f"\n{decrypted_message}")
                print(f"[{self.username}]: ", end="", flush=True)
                
            except Exception as e:
                print(f"[CLIENT] เกิดข้อผิดพลาดในการรับข้อความ: {e}")
                break
                
        self.client_socket.close()
        
    def send_messages(self):
        """รับข้อความจากผู้ใช้และส่งไปยังเซิร์ฟเวอร์"""
        print(f"[CLIENT] เริ่มการแชท (พิมพ์ 'exit' เพื่อออก)")
        
        try:
            while True:
                message = input(f"[{self.username}]: ")
                if message.lower() == 'exit':
                    break
                    
                # เข้ารหัสข้อความ
                encrypted_message = self.cipher.encrypt(f"{self.username}: {message}")
                
                # ส่งข้อความที่เข้ารหัสแล้วไปยังเซิร์ฟเวอร์
                self.client_socket.send(encrypted_message)
                
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"[CLIENT] เกิดข้อผิดพลาดในการส่งข้อความ: {e}")
            
        self.client_socket.close()
        print("[CLIENT] ปิดการเชื่อมต่อ")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="ระบบแชทเข้ารหัสควอนตัม")
    parser.add_argument("mode", choices=["server", "client"], help="โหมดการทำงาน: server หรือ client")
    parser.add_argument("--host", default="localhost", help="โฮสต์ที่จะเชื่อมต่อหรือรัน (ค่าเริ่มต้น: localhost)")
    parser.add_argument("--port", type=int, default=9000, help="พอร์ตที่จะใช้ (ค่าเริ่มต้น: 9000)")
    parser.add_argument("--username", default="Anonymous", help="ชื่อผู้ใช้สำหรับโหมด client (ค่าเริ่มต้น: Anonymous)")
    
    args = parser.parse_args()
    
    if args.mode == "server":
        server = QuantumServer(args.host, args.port)
        try:
            server.start()
        except KeyboardInterrupt:
            print("[SERVER] ปิดเซิร์ฟเวอร์...")
            
    elif args.mode == "client":
        client = QuantumClient(args.host, args.port, args.username)
        client.connect()
