#!/usr/bin/env python3

import socket
from threading import Thread
import random

TERRARIA_SERVER_IP = '127.0.0.1'
TERRARIA_SERVER_PORT = 8822

def log_message(message):
    with open("log.txt", "a") as log_file:
        log_file.write(message + "\n")

def handle_client(client_socket):
    try:
        # Connect to the actual server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.connect((TERRARIA_SERVER_IP, TERRARIA_SERVER_PORT))

            # Create threads to copy data between client and server
            threads = [
                Thread(target=copy_data, args=(client_socket, server_socket, '[Client->Server]:')),
                Thread(target=copy_data, args=(server_socket, client_socket, '[Server->Client]:'))
            ]

            # Start and join threads
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

    except Exception as e:
        error_message = f'Error: {e}'
        print(error_message)
        log_message(error_message)
    finally:
        disconnect_message = 'Client disconnected or server stopped.'
        print(disconnect_message)
        log_message(disconnect_message)

def copy_data(src, dst, prefix):
    try:
        while True:
            # Read the length of the packet (2 bytes)
            data_size = src.recv(2)
            if not data_size:
                break

            # Convert bytes to integer size
            size = int.from_bytes(data_size, 'little') - 2

            # Read the rest of the packet
            data = src.recv(size)
            if not data:
                break

            # Print the received packet details
            message = f'{prefix} ({data[0]}) {data[1:].decode()}'
            print(message)
            log_message(message)

            # Forward the packet to the destination
            dst.sendall(data_size + data)

    except Exception as e:
        error_message = f'Error in copy_data: {e}'
        print(error_message)
        log_message(error_message)

def start_proxy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind(('127.0.0.1', 8823))
        server_socket.listen()
        start_message = f'Proxy server started on 127.0.0.1:8823 Waiting for client...'
        print(start_message)
        log_message(start_message)

        while True:
            client_socket, client_addr = server_socket.accept()
            connect_message = f'Client connected: {client_addr}'
            print(connect_message)
            log_message(connect_message)
            Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_proxy()
