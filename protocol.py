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
      def __init__(self, HOST='0.0.0.0', PORT=8822, MAX_CLIENTS=3, SERVER_LOGGER=None):
          self.server_logger = SERVER_LOGGER
          self.HOST = HOST
          self.PORT = PORT
          self.MAX_CLIENTS = MAX_CLIENTS
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
                    self.server_socket.settimeout(15)
                    client_socket, client_address = self.server_socket.accept()
                    self.server_logger.info(f"IP: {client_address} This client has been connected to your server")
                    if self.shutdown_event.is_set():
                       try:
                          client_socket.sendall(as_server.KICK+b'Disconnected\n')
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
                               client_socket.sendall(as_server.KICK+b'Server is full\n')
                               client_socket.close()
                               self.server_logger.info(f"IP: {client_address} The server is now full. Disconnected this client connection")
                            except Exception as e:
                               self.server_logger.warning(f"IP: {client_address} An error occurred to disconnect. It may be possible that the client is disconnected before [WARN: {e}]")
                            finally:
                               continue
                    self.server_logger.info(f"IP: {client_address} This client is number {len(self.client_threads)+1} that connects to the server from the maximum number of {self.MAX_CLIENTS} clients")
                    if self.thread_pool._shutdown or self.shutdown_event.is_set():
                       try:
                          client_socket.sendall(as_server.KICK+b'Disconnected\n')
                          client_socket.close()
                          self.server_logger.info(f"IP: {client_address} The server is shutting down and the thread pool is disabled. Disconnected this client connection")
                       except Exception as e:
                          self.server_logger.warning(f"IP: {client_address} An error occurred to disconnect. It may be possible that the client is disconnected before [WARN: {e}]")
                       finally:
                          break
                    client_socket.sendall(as_server.NO_KICKS)
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
             self.bind_error = True
          if not self.bind_error:
             print("Hypersecure shell Version 1.0")
             self.server_logger.info(f"HSS server started on {self.HOST}:{self.PORT}")
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
          handle_manager = protocol2.ServerManager(self.server_logger, client_socket, client_address)
          try:
             handshake_passed = handle_manager.try_handshake()
             if handshake_passed:
                auth_passed = handle_manager.req_passwd(True)
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
      def __init__(self, HOST='0.0.0.0', PORT=8822, CLIENT_LOGGER=None):
          self.client_logger=CLIENT_LOGGER
          self.HOST = HOST
          self.PORT = PORT
          self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          self.running = True
          self.client_manager = None
          self.got_kicked = False
          self.retries = 0
          self.max_retries = 3
          self.time_out = False
      def connect(self):
          self.client_logger.info(f"Connecting to HSS server {self.HOST}:{self.PORT}...")
          handshake_passed = False
          auth_passed = False
          self.client_socket.settimeout(15)
          while self.running:
              try:
                  while True:
                      try:
                         self.client_socket.connect((self.HOST, self.PORT))
                         self.client_manager=protocol2.ClientManager(self.client_logger,self.client_socket)
                         self.client_logger.info("Connected")
                         break
                      except socket.timeout:
                         self.client_logger.warning("Connection timeout")
                         self.retires += 1
                         if not self.retries > self.max_retries:
                            self.client_logger.warning(f"Retrying... {self.retries}")
                            continue
                         self.time_out = True
                      except Exception as e:
                         self.client_logger.critical(f"An error occurred while trying to connect [CRITICAL: {e}]")
                         break
                      finally:
                         break
                  if self.time_out:
                     break
                  self.got_kicked=self.client_manager.try_check_and_print_kick_msg()
                  if self.got_kicked:
                     break
                  handshake_passed = self.client_manager.try_handshake()
                  if handshake_passed:
                     auth_passed = self.client_manager.try_auth_passwd()
                     if auth_passed:
                        try:
                           self.client_logger.info("Creating a shell tunnel...")
                           shell.activate(self, self.client_manager)
                        except Exception as e:
                           self.client_logger.error(f"Session shell error [ERROR: {e}]")
                        finally:
                           self.client_logger.info(f"Session shell closed")
                           break
                     else:
                         self.client_logger.info(f"Authentication failed")
                         break
                  else:
                     self.client_logger.critical("Handshake failed, Disconnecting...")
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
          except Exception as e:
                self.client_logger.error(f"Failed to disonnect server [ERROR: {e}]")
