import os
import subprocess
import sys
import tty
import termios
import select
import signal
import fcntl
import struct
from packets import as_server, as_client

def get_terminal_size(fd):
	try:
		s = struct.pack("HHHH", 0, 0, 0, 0)
		size = fcntl.ioctl(fd, termios.TIOCGWINSZ, s)
		rows, cols, _, _ = struct.unpack("HHHH", size)
		return rows, cols
	except:
		return 24, 80  # fallback

def activate(client_instants, client_manager):
	client_socket = client_manager.return_sock()
	old_settings = termios.tcgetattr(sys.stdin)

	def resize_handler(signum, frame):
			rows, cols = get_terminal_size(sys.stdin.fileno())
			client_manager.resize(rows, cols)
	try:
		tty.setraw(sys.stdin.fileno())

		# Sync terminal size
		rows, cols = get_terminal_size(sys.stdin.fileno())
		client_manager.resize(rows, cols)

		# Listen for terminal resize
		signal.signal(signal.SIGWINCH, resize_handler)
		running = True
		while running:
			rlist, _, _ = select.select([sys.stdin, client_socket], [], [])
			if sys.stdin in rlist:
				   data = os.read(sys.stdin.fileno(), 1024)
				   if not data:
                                      break
				   client_manager.shell(data)
			if client_socket in rlist:
				try:
				   data = client_manager.wait_recv_utf8()
				   if data is None:
                                          client_instants.client_logger.critical("Server down")
                                          running = False
                                          break
				   data = data.encode()
				   msg_type = data.decode('utf-8')
				   if msg_type.startswith(as_server.BYE.decode()):
                                          running = False
                                          break
				   if msg.artswith('{"type":"key_rotation"'):
                                                rotation_data = json.loads(msg_type)
                                                if rotation_data["type"] == "key_rotation":
                                                   client_manager.handle_key_rotation(rotation_data)
                                                   continue
				   elif running:
                                        oshell=msg_type
                                        os.write(sys.stdout.fileno(), oshell.encode())
				except Exception as e:
                                       client_instants.client_logger.error(f"Sock shell [ERROR: {e}]")
	finally:
		termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
		try:
			if client_socket.fileno() != -1:
			   client_socket.close()
			   client_instants.client_logger.info("Disconnected")
		except Exception as e:
			client_instants.client_logger.error(f"Failed to disconnect server [ERROR: {e}]")
