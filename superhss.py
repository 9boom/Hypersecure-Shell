#!/usr/bin/env python3

import threading
import socket
import asyncio
import sys
import logging
import signal
import atexit
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextlib import contextmanager

# Import shell modules (make sure these exist)
try:
    import shell, shelld
except ImportError as e:
    print(f"Warning: Could not import shell modules: {e}")
    shell = None
    shelld = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('hss.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)

@contextmanager
def safe_socket_operation(socket_obj, operation_name, address=None):
    """Context manager for safe socket operations"""
    try:
        yield socket_obj
    except socket.error as e:
        addr_str = f" for {address}" if address else ""
        logger.error(f"Socket error during {operation_name}{addr_str}: {e}")
    except Exception as e:
        addr_str = f" for {address}" if address else ""
        logger.error(f"Unexpected error during {operation_name}{addr_str}: {e}")

class HSSServer:
    def __init__(self, HOST='0.0.0.0', PORT=8822, MAX_CLIENTS=3):
        self.HOST = HOST
        self.PORT = PORT
        self.MAX_CLIENTS = MAX_CLIENTS
        self.running = True
        self.client_threads = []
        self.address_already_in_use = False  # Fixed typo: 'used' -> 'use'
        self.server_loop_thread = None
        self.server_socket = None
        self.shutdown_event = threading.Event()
        self.thread_lock = threading.RLock()  # Use RLock for better deadlock prevention
        self.thread_pool = None
        
        # Initialize components
        self._initialize_socket()
        self._initialize_thread_pool()
        
        # Register cleanup function
        atexit.register(self.cleanup_on_exit)
        
    def _initialize_socket(self):
        """Initialize server socket with proper error handling"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Set socket to non-blocking with timeout
            self.server_socket.settimeout(1.0)
            logger.info("Server socket initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize server socket: {e}")
            raise
            
    def _initialize_thread_pool(self):
        """Initialize thread pool with proper error handling"""
        try:
            self.thread_pool = ThreadPoolExecutor(
                max_workers=self.MAX_CLIENTS * 2,
                thread_name_prefix="HSS-Worker"
            )
            logger.info(f"Thread pool initialized with {self.MAX_CLIENTS * 2} workers")
        except Exception as e:
            logger.error(f"Failed to initialize thread pool: {e}")
            raise
            
    def cleanup_on_exit(self):
        """Cleanup function called when Python exits"""
        if self.running:
            logger.info("Performing cleanup on exit")
            self.shutdown(None, None)
            
    def server_loop(self):
        """Main server loop with improved error handling"""
        logger.info("Server loop started")
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        while self.running and not self.shutdown_event.is_set():
            try:
                with safe_socket_operation(self.server_socket, "accept"):
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f"New connection from {client_address}")
                    consecutive_errors = 0  # Reset error counter on successful accept

                if self.shutdown_event.is_set():
                    self._notify_client_shutdown(client_socket, client_address)
                    break

                self.cleanup_threads()
                
                # Check client limit
                with self.thread_lock:
                    active_clients = len([t for t in self.client_threads if not t[0].done()])
                    if active_clients >= self.MAX_CLIENTS:
                        self._reject_client(client_socket, client_address, "Max clients reached")
                        continue

                # Submit client handling to thread pool
                self._submit_client_handler(client_socket, client_address)
                
            except socket.timeout:
                continue  # Normal timeout, just continue
            except socket.error as e:
                if self.running:
                    consecutive_errors += 1
                    logger.warning(f"Socket error in server loop (attempt {consecutive_errors}): {e}")
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error("Too many consecutive socket errors, shutting down")
                        break
                    time.sleep(0.1)  # Brief pause before retry
            except Exception as e:
                if self.running:
                    consecutive_errors += 1
                    logger.error(f"Unexpected error in server loop (attempt {consecutive_errors}): {e}")
                    if False: #consecutive_errors >= max_consecutive_errors:
                        logger.error("Too many consecutive errors, shutting down")
                        break
                    time.sleep(0.1)
            finally:
                self.cleanup_threads()
                
        logger.info("Server loop ended")
        
    def _notify_client_shutdown(self, client_socket, client_address):
        """Notify client of server shutdown"""
        try:
            with safe_socket_operation(client_socket, "shutdown notification", client_address):
                client_socket.sendall(b"SERVER_DEAD\n")
                client_socket.close()
        except Exception as e:
            logger.warning(f"Could not notify {client_address} of shutdown: {e}")
            
    def _reject_client(self, client_socket, client_address, reason):
        """Reject client connection with reason"""
        logger.warning(f"Rejecting client {client_address}: {reason}")
        try:
            with safe_socket_operation(client_socket, "client rejection", client_address):
                client_socket.sendall(b"FORCE_STOP\n")
                client_socket.close()
        except Exception as e:
            logger.warning(f"Error rejecting client {client_address}: {e}")
            
    def _submit_client_handler(self, client_socket, client_address):
        """Submit client handler to thread pool"""
        try:
            if self.thread_pool._shutdown or self.shutdown_event.is_set():
                logger.warning("ThreadPool is shutdown, cannot accept new connections")
                self._notify_client_shutdown(client_socket, client_address)
                return
                
            future = self.thread_pool.submit(self.handle_client, client_socket, client_address)
            with self.thread_lock:
                self.client_threads.append((future, client_socket, client_address))
                logger.debug(f"Client handler submitted for {client_address}")
                
        except RuntimeError as e:
            if "cannot schedule new futures after interpreter shutdown" in str(e):
                logger.info("Python interpreter shutting down, stopping server")
                self.shutdown(None, None)
            else:
                logger.error(f"Runtime error submitting client handler: {e}")
                self._reject_client(client_socket, client_address, "Server error")
        except Exception as e:
            logger.error(f"Unexpected error submitting client handler: {e}")
            self._reject_client(client_socket, client_address, "Server error")
            
    def cleanup_threads(self):
        """Clean up completed threads with better error handling"""
        try:
            with self.thread_lock:
                active_threads = []
                completed_count = 0
                
                for future, sock, addr in self.client_threads:
                    try:
                        if not future.done():
                            active_threads.append((future, sock, addr))
                        else:
                            completed_count += 1
                            # Check if future had an exception
                            try:
                                future.result(timeout=0)  # This will raise if there was an exception
                            except Exception as e:
                                logger.error(f"Client handler for {addr} finished with error: {e}")
                            else:
                                logger.debug(f"Client handler for {addr} completed successfully")
                    except Exception as e:
                        logger.warning(f"Error checking thread status for {addr}: {e}")
                        # Keep thread in active list to avoid losing track of it
                        active_threads.append((future, sock, addr))
                
                if completed_count > 0:
                    logger.info(f"Cleaned up {completed_count} completed client threads")
                    
                self.client_threads = active_threads
                
        except Exception as e:
            logger.error(f"Error during thread cleanup: {e}")
            
    def shutdown(self, signum, frame):
        """Graceful shutdown with improved error handling"""
        if not self.running:
            return
            
        logger.info("Initiating graceful shutdown...")
        self.running = False
        self.shutdown_event.set()

        # Close server socket first to stop accepting new connections
        if self.server_socket:
            try:
                if self.server_socket.fileno() != -1:
                    self.server_socket.close()
                    logger.info("Server socket closed")
            except Exception as e:
                logger.error(f"Error closing server socket: {e}")

        # Wait for server loop to finish
        if self.server_loop_thread and self.server_loop_thread.is_alive():
            logger.info("Waiting for server loop to finish...")
            self.server_loop_thread.join(timeout=5)
            if self.server_loop_thread.is_alive():
                logger.warning("Server loop thread did not finish in time")

        # Close all client connections
        self._close_all_clients()

        # Shutdown thread pool
        if self.thread_pool:
            try:
                logger.info("Shutting down thread pool...")
                self.thread_pool.shutdown(wait=True, timeout=10)
                logger.info("Thread pool shutdown completed")
            except Exception as e:
                logger.error(f"Error shutting down thread pool: {e}")
                
        logger.info("Shutdown completed successfully")
        
    def _close_all_clients(self):
        """Close all client connections"""
        with self.thread_lock:
            client_count = len(self.client_threads)
            if client_count > 0:
                logger.info(f"Closing {client_count} client connections...")
                
            for future, sock, addr in self.client_threads:
                try:
                    with safe_socket_operation(sock, "client shutdown", addr):
                        sock.sendall(b"SERVER_DEAD\n")
                        sock.close()
                    logger.debug(f"Closed connection to {addr}")
                except Exception as e:
                    logger.warning(f"Error closing client {addr}: {e}")
                    
    def bind(self):
        """Bind server with improved error handling"""
        try:
            self.server_socket.bind((self.HOST, self.PORT))
            logger.info(f"Successfully bound to {self.HOST}:{self.PORT}")
        except socket.error as e:
            self.address_already_in_use = True
            if e.errno == 98:  # Address already in use
                logger.error(f"Address {self.HOST}:{self.PORT} is already in use")
            else:
                logger.error(f"Socket bind error: {e}")
            return False
        except Exception as e:
            self.address_already_in_use = True
            logger.error(f"Unexpected bind error: {e}")
            return False
            
        if self.address_already_in_use:
            return False
            
        try:
            print("Hypersecure Shell Version 1.0")
            print(f"HSS server started on {self.HOST}:{self.PORT}")
            
            self.server_socket.listen(self.MAX_CLIENTS)
            logger.info(f"Server listening with max {self.MAX_CLIENTS} clients")
            
            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self.shutdown)   # CTRL+C
            signal.signal(signal.SIGTERM, self.shutdown)  # Terminate signal
            
            # Start server loop thread
            self.server_loop_thread = threading.Thread(
                target=self.server_loop, 
                daemon=True,
                name="HSS-ServerLoop"
            )
            self.server_loop_thread.start()
            
            print("Waiting for connections...")
            
            # Keep main thread alive
            try:
                while self.running and not self.shutdown_event.is_set():
                    if not self.server_loop_thread.is_alive():
                        logger.warning("Server loop thread died unexpectedly")
                        break
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Received keyboard interrupt")
                self.shutdown(None, None)
                
        except Exception as e:
            logger.error(f"Server startup error: {e}")
            self.shutdown(None, None)
            return False
            
        return True
        
    def handle_client(self, client_socket, client_address):
        """Handle individual client connection with comprehensive error handling"""
        logger.info(f"Handling client {client_address}")
        check_valid_hss_client = False
        
        try:
            # Set socket timeout for handshake
            client_socket.settimeout(10)
            
            # Send handshake
            with safe_socket_operation(client_socket, "handshake send", client_address):
                client_socket.sendall(b"HSS_CLIENT_HANDSHAKE\n")
            
            # Receive client response
            try:
                data = client_socket.recv(1024)
            except socket.timeout:
                logger.warning(f"Client {client_address} handshake timed out")
                return
            except socket.error as e:
                logger.warning(f"Socket error during handshake with {client_address}: {e}")
                return
                
            if not data:
                logger.warning(f"No handshake data received from {client_address}")
                return
                
            try:
                data_str = data.decode('utf-8').strip()
            except UnicodeDecodeError as e:
                logger.warning(f"Invalid UTF-8 data from {client_address}: {e}")
                return
                
            # Validate handshake
            if data_str.startswith("JOIN_SERVER"):
                check_valid_hss_client = True
                logger.info(f"Handshake successful with {client_address}")
            else:
                logger.warning(f"Invalid handshake from {client_address}: {data_str[:50]}")
                
            # Handle validated client
            if check_valid_hss_client:
                if shelld is None:
                    logger.error("shelld module not available")
                    with safe_socket_operation(client_socket, "error notification", client_address):
                        client_socket.sendall(b"SERVER_ERROR: Shell not available\n")
                    return
                    
                try:
                    logger.info(f"Starting shell session for {client_address}")
                    shelld.start_session_shell(client_socket)
                except Exception as e:
                    logger.error(f"Session shell error for {client_address}: {e}")
                finally:
                    logger.info(f"Shell session ended for {client_address}")
            else:
                logger.warning(f"Rejecting invalid client {client_address}")
                with safe_socket_operation(client_socket, "rejection", client_address):
                    client_socket.sendall(b"FORCE_STOP\n")
                    
        except Exception as e:
            logger.error(f"Unexpected error handling client {client_address}: {e}")
        finally:
            # Ensure socket is closed
            try:
                if client_socket.fileno() != -1:
                    client_socket.close()
                    logger.debug(f"Socket closed for {client_address}")
            except Exception as e:
                logger.warning(f"Error closing socket for {client_address}: {e}")

class HSSClient:
    def __init__(self, HOST='127.0.0.1', PORT=8822):  # Default to localhost
        self.HOST = HOST
        self.PORT = PORT
        self.client_socket = None
        self.running = True
        
    def connect(self):
        """Connect to HSS server with improved error handling"""
        logger.info(f"Connecting to HSS server at {self.HOST}:{self.PORT}")
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)
            
            # Attempt connection
            try:
                self.client_socket.connect((self.HOST, self.PORT))
                logger.info(f"Connected to {self.HOST}:{self.PORT}")
            except socket.timeout:
                logger.error("Connection timed out")
                return False
            except socket.gaierror as e:
                logger.error(f"DNS resolution failed: {e}")
                return False
            except ConnectionRefusedError:
                logger.error("Connection refused - server may not be running")
                return False
            except Exception as e:
                logger.error(f"Connection failed: {e}")
                return False

            # Handle handshake
            if not self._handle_handshake():
                return False
                
            # Start shell session
            if shell is None:
                logger.error("shell module not available")
                return False
                
            logger.info("Starting shell session...")
            shell.start_session_shell(self.client_socket)
            
            return True
            
        except Exception as e:
            logger.error(f"Unexpected connection error: {e}")
            return False
        finally:
            self._cleanup()
            
    def _handle_handshake(self):
        """Handle client-server handshake"""
        try:
            # Receive server handshake
            data = self.client_socket.recv(1024)
            if not data:
                logger.error("No handshake received from server")
                return False
                
            try:
                data_str = data.decode('utf-8').strip()
            except UnicodeDecodeError as e:
                logger.error(f"Invalid handshake data: {e}")
                return False
                
            # Validate server handshake
            if not data_str.startswith("HSS_CLIENT_HANDSHAKE"):
                logger.error(f"Invalid server handshake: {data_str[:50]}")
                return False
                
            # Send join request
            with safe_socket_operation(self.client_socket, "join request"):
                self.client_socket.sendall(b"JOIN_SERVER!\n")
                
            logger.info("Handshake completed successfully")
            return True
            
        except socket.timeout:
            logger.error("Handshake timed out")
            return False
        except Exception as e:
            logger.error(f"Handshake error: {e}")
            return False
            
    def _cleanup(self):
        """Clean up client resources"""
        logger.info("Cleaning up client connection")
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                logger.warning(f"Error closing client socket: {e}")

def parse_arguments():
    """Parse command line arguments with better error handling"""
    if len(sys.argv) < 2:
        return None, {}
        
    mode = sys.argv[1].lower()
    if mode not in ['server', 'remote']:
        return None, {}
        
    args = {'mode': mode}
    i = 2
    
    try:
        while i < len(sys.argv):
            arg = sys.argv[i]
            
            if arg == '-p' and i + 1 < len(sys.argv):
                try:
                    args['port'] = int(sys.argv[i + 1])
                    if not (1 <= args['port'] <= 65535):
                        raise ValueError("Port must be between 1 and 65535")
                except ValueError as e:
                    logger.error(f"Invalid port: {e}")
                    return None, {}
                i += 2
            elif arg == '-m' and i + 1 < len(sys.argv) and mode == 'server':
                try:
                    args['max_clients'] = int(sys.argv[i + 1])
                    if args['max_clients'] < 1:
                        raise ValueError("Max clients must be positive")
                except ValueError as e:
                    logger.error(f"Invalid max clients: {e}")
                    return None, {}
                i += 2
            elif arg == '-u' and i + 1 < len(sys.argv) and mode == 'remote':
                args['username'] = sys.argv[i + 1]
                i += 2
            elif arg == '-w' and i + 1 < len(sys.argv) and mode == 'remote':
                args['password'] = sys.argv[i + 1]
                i += 2
            elif not arg.startswith('-'):
                args['host'] = arg
                i += 1
            else:
                i += 1
                
    except IndexError:
        logger.error("Missing argument value")
        return None, {}
        
    return mode, args

def help_the_user():
    """Display help information"""
    print("Usage: hss [server [-p port] [-m max_clients] [host] | remote [-p port] [-u username] [-w password] [address]]")
    print("Examples:")
    print("  hss server -p 8822 -m 8 0.0.0.0        # Start server on all interfaces")
    print("  hss remote -p 8822 -u kali 192.168.1.1  # Connect to remote server")
    print("  hss server                               # Start server with defaults")
    print("  hss remote 127.0.0.1                    # Connect to localhost")

if __name__ == '__main__':
    try:
        mode, args = parse_arguments()
        
        if mode is None:
            help_the_user()
            sys.exit(1)
            
        if mode == "server":
            host = args.get('host', '0.0.0.0')
            port = args.get('port', 8822)
            max_clients = args.get('max_clients', 3)
            
            logger.info(f"Starting server: {host}:{port} (max clients: {max_clients})")
            server = HSSServer(HOST=host, PORT=port, MAX_CLIENTS=max_clients)
            
            if not server.bind():
                logger.error("Failed to start server")
                sys.exit(1)
                
        elif mode == "remote":
            host = args.get('host', '127.0.0.1')
            port = args.get('port', 8822)
            username = args.get('username')
            password = args.get('password')
            
            logger.info(f"Connecting as client to: {host}:{port}")
            if username:
                logger.info(f"Username: {username}")
                
            client = HSSClient(HOST=host, PORT=port)
            if not client.connect():
                logger.error("Failed to connect to server")
                sys.exit(1)
                
    except KeyboardInterrupt:
        logger.info("Program interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Program error: {e}")
        sys.exit(1)
