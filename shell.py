import os
import subprocess
import sys
import tty
import termios
import select
import signal
import fcntl
import struct

def get_terminal_size(fd):
    try:
        s = struct.pack("HHHH", 0, 0, 0, 0)
        size = fcntl.ioctl(fd, termios.TIOCGWINSZ, s)
        rows, cols, _, _ = struct.unpack("HHHH", size)
        return rows, cols
    except:
        return 24, 80  # fallback

def activate(connection,client_instants):
    old_settings = termios.tcgetattr(sys.stdin)

    def resize_handler(signum, frame):
            rows, cols = get_terminal_size(sys.stdin.fileno())
            command_resize = f"SHELL_RESIZE_REQUEST:{rows}:{cols}\n".encode()
            connection.sendall(command_resize)
    try:
        tty.setraw(sys.stdin.fileno())

        # Sync terminal size
        rows, cols = get_terminal_size(sys.stdin.fileno())
        command_resize = f"SHELL_RESIZE_REQUEST:{rows}:{cols}\n".encode()
        connection.sendall(command_resize)

        # Listen for terminal resize
        signal.signal(signal.SIGWINCH, resize_handler)

        while True:
            rlist, _, _ = select.select([sys.stdin, connection], [], [])
            if sys.stdin in rlist:
                   data = os.read(sys.stdin.fileno(), 1024)
                   if not data:
                      break
                   connection.sendall(data)
            if connection in rlist:
                try:
                   data = connection.recv(1024)
                   if not data:
                      client_instants.client_logger.critical("Server down")
                      break
                   special_cmd_checker = data.decode('utf-8')
                   if special_cmd_checker.startswith('SERVER_DEAD'):
                      client_instants.client_logger.info("Server disconnected")
                      break
                   if special_cmd_checker.startswith('SAY_BYE'):
                      # Something bugs
                      #client_instants.client_logger.info("Bye bye")
                      break
                   if special_cmd_checker.startswith('FORCE_STOP'):
                      client_instants.client_logger.critical("Rejected by Server")
                      break
                   os.write(sys.stdout.fileno(), data)
                except Exception as e:
                   client_instants.client_logger.error(f"Sock shell [ERROR: {e}]")

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        try:
            if connection.fileno() != -1:
               connection.close()
               client_instants.client_logger.info("Disconnected")
        except Exception as e:
            client_instants.client_logger.error(f"Failed to disconnect server [ERROR: {e}]")
