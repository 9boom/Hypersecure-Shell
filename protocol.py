#!/usr/bin/env python3

import threading
import socket
import sys
import time
import shell, shelld
import protocol2
import signal
import atexit
from concurrent.futures import ThreadPoolExecutor
from packets import as_server, as_client

class HSSServer:
      def __init__(
        self,
        HOST='0.0.0.0',
        PORT=8822,
        MAX_CLIENTS=3,
        SERVER_LOGGER=None,
        TIMEOUT=15,
        TIME_SLEEP_BEFORE_ENCRYPT=1,
        TIME_SLEEP_BEFORE_DISCONNECTED_FROM_KICK=2,
        MAX_MESSAGE_AGE=30,
        BUFFER_SIZE=4096,
        USE_PASSWORD=0,
        PASSWORD_TO_LOGIN="",
        USE_ZKP=0,
        ZKP_NUM_ROUND = 300,
        USE_WORMHOLE=0,
        WORMHOLE_ENTRY_POINT_HOST="127.0.0.1",
        WORMHOLE_ENTRY_POINT_PORT=9999,
    ):
          self.server_logger = SERVER_LOGGER
          self.HOST = HOST
          self.PORT = PORT
          self.MAX_CLIENTS = MAX_CLIENTS
          self.timeout = TIMEOUT
          self.time_sleep_before_encrypt = TIME_SLEEP_BEFORE_ENCRYPT
          self.time_sleep_before_disconnected_from_kick = TIME_SLEEP_BEFORE_DISCONNECTED_FROM_KICK
          self.max_message_age = MAX_MESSAGE_AGE
          self.buffer_size = BUFFER_SIZE
          self.use_password = bool(USE_PASSWORD)
          self.password_to_login = PASSWORD_TO_LOGIN
          self.use_ZKP = bool(USE_ZKP)
          self.zkp_num_round = ZKP_NUM_ROUND
          self.use_wormhole = bool(USE_WORMHOLE)
          self.wormhole_entry_point_host = WORMHOLE_ENTRY_POINT_HOST

          self.running = True
          self.client_threads = []
          self.bind_error = False
          self.server_loop_thread = threading.Thread(target=self.server_loop,daemon=True)
          self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          # Set socket options for reuse
          self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
          self.shutdown_event = threading.Event()
          self.thread_lock = threading.Lock()
          self.thread_pool = ThreadPoolExecutor(max_workers=self.MAX_CLIENTS * 2)
          atexit.register(self.clean_after_exit)
      def clean_after_exit(self):
         if self.running:
             self.shutdown(None, None)
      def server_loop(self):
          while self.running and not self.shutdown_event.is_set():
                try:
                    self.server_socket.settimeout(self.timeout)
                    client_socket, client_address = self.server_socket.accept()
                    self.server_logger.info(f"IP: {client_address} This client has been connected to your server")
                    if self.shutdown_event.is_set():
                       try:
                          client_socket.sendall(b"Server is'nt avalible")
                          client_socket.close()
                          self.server_logger.info(f"IP: {client_address} The shutdown function of the server is running. Disconnected this client connection")
                       except Exception as e:
                          self.server_logger.warning(f"IP: {client_address} An error occurred to disconnect. It may be possible that the client is disconnected before [WARN: {e}]")
                       finally:
                          break
                    self.cleanup_threads()
                    with self.thread_lock:
                         if len(self.client_threads) >= self.MAX_CLIENTS:
                            try:
                               client_socket.sendall(b'Server is full')
                               client_socket.close()
                               self.server_logger.info(f"IP: {client_address} The server is now full. Disconnected this client connection")
                            except Exception as e:
                               self.server_logger.warning(f"IP: {client_address} An error occurred to disconnect. It may be possible that the client is disconnected before [WARN: {e}]")
                            finally:
                               continue
                    self.server_logger.info(f"IP: {client_address} This client is number {len(self.client_threads)+1} that connects to the server from the maximum number of {self.MAX_CLIENTS} clients")
                    if self.thread_pool._shutdown or self.shutdown_event.is_set():
                       try:
                          client_socket.sendall(b"Server is'nt avalible")
                          client_socket.close()
                          self.server_logger.info(f"IP: {client_address} The server is shutting down and the thread pool is disabled. Disconnected this client connection")
                       except Exception as e:
                          self.server_logger.warning(f"IP: {client_address} An error occurred to disconnect. It may be possible that the client is disconnected before [WARN: {e}]")
                       finally:
                          break
                    #IM FREEEEEE
                    client_socket.sendall(b"AUTH_LAYER0_PASSED")
                    try:
                       future = self.thread_pool.submit(self.handle_client,client_socket,client_address)
                       with self.thread_lock:
                            self.client_threads.append((future, client_socket, client_address))
                       self.server_logger.info(f"IP {client_address} This client is entering the authentication process.")
                    except Exception as e:
                        self.server_logger.error(f"IP {client_address} An error occurred to try to enter the authentication process [ERROR: {e}]")
                        try:
                           client_socket.sendall(as_server.KICK+b'Disconnected\n')
                           client_socket.close()
                           self.server_logger.info(f"IP {client_address} An error occurred to try to enter the authentication mode. Disconnected this client connection")
                        except Exception as e:
                           self.server_logger.warning(f"IP: {client_address} An error occurred to disconnect. It may be possible that the client is disconnected before [WARN: {e}]")
                except socket.timeout:
                    continue
                except Exception as e:
                    self.server_logger.critical(f"Server loop error [CRITICAL: {e}]")
                finally:
                    self.cleanup_threads()
          self.server_logger.info("Server loop ended")
      def cleanup_threads(self):
          active_threads = []
          with self.thread_lock:
             try:
                  for future, sock, addr in self.client_threads:
                      if not future.done():
                         active_threads.append((future, sock, addr))
                      else:
                         self.server_logger.info(f"IP: {addr} This client has disconnected. But also in the list of work clients Cleaning")
             except Exception as e:
                    self.server_logger.error(f"Error in cleaning threads [ERROR: {e}]")
             self.client_threads = active_threads
      def shutdown(self,signum,frame):
          if not self.running:
             return
          self.running = False
          self.shutdown_event.set()
          self.server_logger.info("Shutting down...")
          print("Shutting down...")
          self.cleanup_threads()
          if self.server_socket.fileno() != -1:
             try:
                self.server_socket.close()
                self.server_logger.info("Server has closed")
             except Exception as e:
                self.server_logger.error(f"An error occurred to close the server [ERROR: {e}]")
          if self.server_loop_thread.is_alive():
             self.server_logger.info("Waiting for server loop closed...")
             self.server_loop_thread.join(timeout=3)
          for _, sock, addr in self.client_threads:
              try:
                 sock.close()
                 self.server_logger.info(f"IP: {addr} Because the server is closing. Disconnected this client connection")
              except Exception as e:
                 self.server_logger.warning(f"IP: {client_address} An error occurred to disconnect. It may be possible that the client is disconnected before [WARNING: {e}]")
          try:
             self.thread_pool.shutdown(wait=True)
             self.server_logger.info("Threads pool have been shutting down...")
          except Exception as e:
             self.server_logger.error(f"Shutdown Thread Pool is not successful [ERROR: {e}]")
          self.server_logger.info("Waiting until the server loop will report that it is completely shutdown...")
      def bind(self):
          try:
             self.server_socket.bind((self.HOST,self.PORT))
          except Exception as e:
             self.server_logger.critical(f"An error occurred to start the server socket [CRITICAL: {e}]")
             print(f"An error occurred to start the server socket [CRITICAL: {e}]")
             self.bind_error = True
          if not self.bind_error:
             print("Hypersecure shell Version 1.0")
             self.server_logger.info(f"Running server {self.HOST}:{self.PORT}")
             print(f"Running server {self.HOST}:{self.PORT}")
             try:
                 self.server_socket.listen(self.MAX_CLIENTS)
                 # Set up signal handlers for graceful shutdown
                 signal.signal(signal.SIGINT, self.shutdown)
                 signal.signal(signal.SIGTERM, self.shutdown)
                 self.server_logger.info(f"Waiting for connection... (max clients: {self.MAX_CLIENTS})")
                 self.server_loop_thread.start()
                 try:
                    while True:
                          self.server_loop_thread.join(timeout=1)
                          if not self.server_loop_thread.is_alive():
                             self.server_logger.info("***Graceful Shutdown***")
                             break
                 except KeyboardInterrupt:
                    self.shutdown(None, None)
             except Exception as e:
                 self.server_logger.CRITICAL(f"An error occurred in the server setup process [CRITICAL: {e}]")
                 self.shutdown(None, None)
      def handle_client(self,client_socket,client_address):
          auth_passed = False
          handshake_passed = False
          handle_manager = protocol2.ServerManager(self.server_logger, client_socket, client_address, self.buffer_size, self.max_message_age, self.password_to_login, self.use_ZKP, self.zkp_num_round)
          try:
             handshake_passed = handle_manager.try_handshake()
             if handshake_passed:
                auth_passed = handle_manager.req_passwd(self.use_password)
                if auth_passed:
                   try:
                      self.server_logger.info(f"IP: {client_address} Starting shell...")
                      shelld.activate(self, handle_manager)
                   except Exception as e:
                      self.server_logger.error(f"\nIP: {client_address} Session shell error [ERROR: {e}]")
                   finally:
                      self.server_logger.info(f"IP: {client_address} Session shell closed")
                else:
                    self.server_logger.info(f"IP: {client_address} Authentication failed, Disconnecting")
             else:
                 self.server_logger.info(f"IP: {client_address} Handshake failed, Disconnecting")
          except Exception as e:
             self.server_logger.error(f"IP: {client_address} An error occurred during the authentication [ERROR: {e}]")
          finally:
             try:
                if client_socket.fileno() != -1:
                   client_socket.close()
                   self.server_logger.info(f"\nIP: {client_address} Disconnected this client connection")
             except Exception as e:
                self.server_logger.error(f"\nIP: {client_address} An error occurred while trying to disconnect this client connection [ERROR: {e}]")

class HSSClient:
      def __init__(
        self,
        HOST='0.0.0.0',
        PORT=8822,
        CLIENT_LOGGER=None,
        TIMEOUT=15,
        MAX_RETRIES=3,
        PASSWORD="",
        BUFFER_SIZE=8192,
        MAX_MESSAGE_AGE=30
    ):
          self.client_logger = CLIENT_LOGGER
          self.HOST = HOST
          self.PORT = PORT
          self.timeout = TIMEOUT
          self.max_retries = MAX_RETRIES
          self.password = PASSWORD
          self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          self.running = True
          self.client_manager = None
          self.got_kicked = False
          self.retries = 0
          self.max_retries = 3
          self.time_out = False
          self.connection_failed = False
          self.buffer_size = BUFFER_SIZE
          self.max_messagge_age = MAX_MESSAGE_AGE
      def connect(self):
          self.client_logger.info(f"Connecting {self.HOST}:{self.PORT}...")
          print(f"Connecting {self.HOST}:{self.PORT}...")
          handshake_passed = False
          auth_passed = False
          self.client_socket.settimeout(self.timeout)
          while self.running:
              try:
                  while True:
                      try:
                         self.client_socket.connect((self.HOST, self.PORT))
                         self.client_logger.info("Connected")
                         print("Connected")
                         break
                      except socket.timeout:
                         self.client_logger.warning("Connection timeout")
                         print("Connection timeout")
                         self.retires += 1
                         if not self.retries > self.max_retries:
                            self.client_logger.warning(f"Retrying... {self.retries}")
                            print("Retrying...")
                            continue
                         self.time_out = True
                      except Exception as e:
                         self.client_logger.critical(f"An error occurred while trying to connect [CRITICAL: {e}]")
                         print(f"An error occurred while trying to connect [CRITICAL: {e}]")
                         self.connection_failed = True
                         break
                      finally:
                         break
                  if self.time_out or self.connection_failed:
                     break
                  #self.got_kicked=self.client_manager.try_check_and_print_kick_msg()
                  #if self.got_kicked:
                  #   break
                  _auth_layer0 = self.client_socket.recv(1024)
                  _auth_layer0 = _auth_layer0.decode('utf-8')
                  if _auth_layer0.startswith("AUTH_LAYER0_PASSED"):
                     pass
                  else:
                     self.client_logger.critical(f"You got kick by server: [REASON: {_auth_layer0}]")
                     print(f"You got kick by server: [REASON: {_auth_layer0}]")
                     break
                  self.client_manager=protocol2.ClientManager(self.client_logger,self.client_socket,self.buffer_size,self.max_messagge_age, self.password)
                  handshake_passed = self.client_manager.try_handshake()
                  if handshake_passed:
                     auth_passed = self.client_manager.try_auth_passwd()
                     if auth_passed:
                        try:
                           self.client_logger.info("Creating a shell tunnel...")
                           print("Creating a shell tunnel...")
                           shell.activate(self, self.client_manager)
                        except Exception as e:
                           self.client_logger.error(f"Session shell error [ERROR: {e}]")
                        finally:
                           self.client_logger.info(f"Session shell closed")
                           print(f"Session shell closed")
                           break
                     else:
                         self.client_logger.info(f"Authentication failed")
                         print(f"Authentication failed")
                         break
                  else:
                     self.client_logger.critical("Handshake failed, Disconnecting...")
                     print("Handshake failed")
                     break
              except Exception as e:
                  self.client_logger.critical(f"Client loop error [CRITICAL: {e}]")
              finally:
                  self.client_logger.info("Client loop closed")
                  break
          try:
             if self.client_socket.fileno() != -1:
                self.client_socket.close()
                self.client_logger.info(f"Disconnected")
                print("Disconnected")
          except Exception as e:
                self.client_logger.error(f"Failed to disonnect server [ERROR: {e}]")