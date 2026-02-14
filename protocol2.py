# PROTOCOL HELPER
# ALL COMMUNICATION LOGIC HERE - PLAINTEXT VERSION (NO ENCRYPTION)

import heapq
import threading
import time
from threading import Thread
from packets import as_server, as_client
import socket
import json
import os
import sys
import struct
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass

# Configuration
SESSION_TIMEOUT = 3600
MAX_MESSAGE_AGE = 30
BUFFER_SIZE = 8192

@dataclass
class SessionInfo:
    socket: socket.socket
    address: tuple
    authenticated: bool
    join_time: float
    session_id: str
    message_nonces: set

class PlaintextProtocol:
    """Simple plaintext communication without encryption"""
    
    def __init__(self, session_id: str):
        self.session_id = session_id
    
    def send(self, data: str) -> bytes:
        """Convert string to bytes for sending"""
        if isinstance(data, str):
            return data.encode('utf-8')
        return data
    
    def receive(self, data: bytes) -> str:
        """Convert bytes to string for receiving"""
        if isinstance(data, bytes):
            return data.decode('utf-8')
        return data

class ProtocolServer:
    def __init__(self, host: str, port: int, logger, password: str = "password", max_connections: int = 5, buffer_size: int = BUFFER_SIZE):
        self.host = host
        self.port = port
        self.logger = logger
        self.password = password
        self.max_connections = max_connections
        self.buffer_size = buffer_size
        self.server_socket = None
        self.sessions: Dict[str, SessionInfo] = {}
        self.session_lock = threading.Lock()
        self.running = False

    def send_large_data(self, client_socket: socket.socket, data: bytes):
        """Send data with length prefix"""
        length = len(data)
        client_socket.sendall(struct.pack('!I', length))
        client_socket.sendall(data)

    def receive_large_data(self, client_socket: socket.socket) -> bytes:
        """Receive data with length prefix"""
        length_data = b''
        while len(length_data) < 4:
            chunk = client_socket.recv(4 - len(length_data))
            if not chunk:
                raise ConnectionError("Connection closed")
            length_data += chunk
        
        length = struct.unpack('!I', length_data)[0]
        data = b''
        while len(data) < length:
            chunk = client_socket.recv(min(self.buffer_size, length - len(data)))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def start(self):
        """Start the server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            self.running = True
            self.logger.info(f"[Plaintext Protocol] Server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    self.logger.info(f"[Plaintext Protocol] New connection from {client_address}")
                    Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True).start()
                except Exception as e:
                    if self.running:
                        self.logger.error(f"[Plaintext Protocol] Accept error: {e}")
        except Exception as e:
            self.logger.critical(f"[Plaintext Protocol] Server error: {e}")
        finally:
            self.stop()

    def handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle individual client connection"""
        session_id = str(uuid.uuid4())
        protocol = PlaintextProtocol(session_id)
        
        try:
            # Send session info to client
            server_info = {
                "session_id": session_id,
                "server_name": "Plaintext Server",
                "timestamp": int(time.time())
            }
            self.send_large_data(client_socket, json.dumps(server_info).encode('utf-8'))
            self.logger.info(f"[Plaintext Protocol] Session created: {session_id}")
            
            # Wait for client response
            client_data = self.receive_large_data(client_socket)
            client_info = json.loads(client_data.decode('utf-8'))
            self.logger.info(f"[Plaintext Protocol] Client connected: {client_info.get('client_name', 'Unknown')}")
            
            # Create session
            with self.session_lock:
                self.sessions[session_id] = SessionInfo(
                    socket=client_socket,
                    address=client_address,
                    authenticated=False,
                    join_time=time.time(),
                    session_id=session_id,
                    message_nonces=set()
                )
            
            # Send welcome message
            welcome_msg = protocol.send("Welcome to Plaintext Server!")
            self.send_large_data(client_socket, welcome_msg)
            
            # Authentication
            if not self.authenticate_client(session_id, protocol):
                self.logger.warning(f"[Plaintext Protocol] Authentication failed for {session_id}")
                self.cleanup_session(session_id)
                return
            
            self.logger.info(f"[Plaintext Protocol] Client authenticated: {session_id}")
            
            # Main communication loop
            while self.running:
                try:
                    data = self.receive_large_data(client_socket)
                    if not data:
                        break
                    
                    message = protocol.receive(data)
                    self.handle_message(session_id, message, protocol)
                    
                except Exception as e:
                    self.logger.error(f"[Plaintext Protocol] Communication error: {e}")
                    break
                    
        except Exception as e:
            self.logger.error(f"[Plaintext Protocol] Client handler error: {e}")
        finally:
            self.cleanup_session(session_id)
            try:
                client_socket.close()
            except:
                pass

    def authenticate_client(self, session_id: str, protocol: PlaintextProtocol) -> bool:
        """Simple password authentication"""
        try:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            # Check if password is required
            if not self.password or self.password == "":
                # No password required
                auth_msg = protocol.send(as_server.AUTH_PASSED.decode())
                self.send_large_data(session.socket, auth_msg)
                session.authenticated = True
                return True
            
            # Request password
            request_msg = protocol.send(as_server.ZKP_REQUEST.decode())
            self.send_large_data(session.socket, request_msg)
            
            # Wait for password
            data = self.receive_large_data(session.socket)
            received = protocol.receive(data)
            
            if received.startswith(as_client.PASSWORD.decode()):
                password_attempt = received[len(as_client.PASSWORD.decode()):].strip()
                
                if password_attempt == self.password:
                    auth_msg = protocol.send(as_server.AUTH_PASSED.decode())
                    self.send_large_data(session.socket, auth_msg)
                    session.authenticated = True
                    return True
                else:
                    fail_msg = protocol.send(as_server.AUTH_FAILED.decode())
                    self.send_large_data(session.socket, fail_msg)
                    return False
            
            return False
            
        except Exception as e:
            self.logger.error(f"[Plaintext Protocol] Authentication error: {e}")
            return False

    def handle_message(self, session_id: str, message: str, protocol: PlaintextProtocol):
        """Handle incoming messages"""
        session = self.sessions.get(session_id)
        if not session:
            return
        
        # Process different message types
        if message.startswith(as_client.SHELL.decode()):
            command = message[len(as_client.SHELL.decode()):].strip()
            self.logger.info(f"[Shell Command] {command}")
            # Handle shell command
            
        elif message.startswith(as_client.RESIZE.decode()):
            size = message[len(as_client.RESIZE.decode()):].strip()
            self.logger.info(f"[Resize] {size}")
            # Handle resize
            
        else:
            self.logger.info(f"[Message] {message}")

    def cleanup_session(self, session_id: str):
        """Clean up session"""
        with self.session_lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                self.logger.info(f"[Plaintext Protocol] Session cleaned up: {session_id}")

    def stop(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.logger.info("[Plaintext Protocol] Server stopped")

    def send_to_session(self, session_id: str, message: str):
        """Send message to specific session"""
        session = self.sessions.get(session_id)
        if session:
            protocol = PlaintextProtocol(session_id)
            data = protocol.send(message)
            self.send_large_data(session.socket, data)

    def broadcast(self, message: str, exclude_session: str = None):
        """Broadcast message to all sessions"""
        with self.session_lock:
            for sid, session in self.sessions.items():
                if sid != exclude_session and session.authenticated:
                    try:
                        self.send_to_session(sid, message)
                    except:
                        pass

class ProtocolClient:
    def __init__(self, host: str, port: int, logger, password: str = "password", buffer_size: int = BUFFER_SIZE):
        self.host = host
        self.port = port
        self.logger = logger
        self.password = password
        self.buffer_size = buffer_size
        self.client_socket = None
        self.protocol = None
        self.connected = False
        self.session_id = None

    def send_large_data(self, data: bytes):
        """Send data with length prefix"""
        length = len(data)
        self.client_socket.sendall(struct.pack('!I', length))
        self.client_socket.sendall(data)

    def receive_large_data(self) -> bytes:
        """Receive data with length prefix"""
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
        """Simple handshake without encryption"""
        try:
            # Receive server info
            server_data = self.receive_large_data()
            server_info = json.loads(server_data.decode('utf-8'))
            self.session_id = server_info["session_id"]
            
            self.logger.info(f"[Plaintext Protocol] Established session: {self.session_id}")
            
            # Send client info
            client_info = {
                "client_name": "Plaintext Client",
                "timestamp": int(time.time())
            }
            self.send_large_data(json.dumps(client_info).encode('utf-8'))
            
            # Initialize protocol
            self.protocol = PlaintextProtocol(self.session_id)
            
            # Receive welcome message
            welcome = self.receive_large_data()
            if welcome:
                msg = self.protocol.receive(welcome)
                self.logger.info(f"[Server] {msg}")
            
            self.connected = True
            self.logger.info(f"[Plaintext Protocol] Connection established")
            
        except Exception as e:
            self.logger.info(f"[Plaintext Protocol] Handshake error: {e}")
            self.disconnect()
            raise

    def disconnect(self):
        """Disconnect from server"""
        self.connected = False
        try:
            self.client_socket.close()
        except:
            pass
        self.logger.info("\n[Plaintext Protocol] Disconnected")

    def return_sock(self):
        """Return socket object"""
        return self.client_socket

    def start(self):
        """Connect to server"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.logger.info(f"[Plaintext Protocol] Connected to {self.host}:{self.port}")
        except Exception as e:
            self.logger.error(f"[Plaintext Protocol] Connection failed: {e}")
            raise

    def send_message(self, message: str):
        """Send message to server"""
        try:
            if message.strip() and self.connected:
                data = self.protocol.send(message)
                self.send_large_data(data)
        except Exception as e:
            self.logger.critical(f"[CLIENT] Send error: {e}")

    def try_handshake(self):
        """Attempt handshake"""
        self.logger.info("Performing plaintext handshake...")
        try:
            self.handshake()
            return True
        except Exception as e:
            self.logger.critical(f"[Plaintext Protocol] Handshake failed: {e}")
            return False

    def try_auth_passwd(self):
        """Attempt password authentication"""
        try:
            data = self.wait_recv_utf8()
            if data and data.startswith(as_server.AUTH_PASSED.decode()):
                return True
            elif data and data.startswith(as_server.ZKP_REQUEST.decode()):
                # Password requested
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
        """Check for kick messages"""
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
        """Send shell command"""
        self.send_message(as_client.SHELL.decode() + cmd_exec.decode() + '\n')

    def resize(self, rows: str, cols: str):
        """Send resize command"""
        self.send_message(as_client.RESIZE.decode() + f"{rows}:{cols}\n")

    def wait_recv_utf8(self):
        """Wait and receive UTF-8 message"""
        try:
            data = self.receive_large_data()
            if not data:
                self.logger.info("[RECV] Server disconnected")
                self.disconnect()
                return None
            
            message = self.protocol.receive(data)
            return message
            
        except Exception as e:
            if self.connected:
                self.logger.critical(f"[RECV] Receive error: {e}")
            return None
