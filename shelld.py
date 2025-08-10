import os
import pty
import subprocess
import sys
import tty
import termios
import select
import signal
import fcntl
import struct
import signal
from packets import as_server, as_client

def get_terminal_size(fd):
    try:
        s = struct.pack("HHHH", 0, 0, 0, 0)
        size = fcntl.ioctl(fd, termios.TIOCGWINSZ, s)
        rows, cols, _, _ = struct.unpack("HHHH", size)
        return rows, cols
    except:
        return 24, 80  # fallback

def set_pty_winsize(fd, rows, cols):
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)

def activate(server_instants, handle_manager):
    client_socket = handle_manager.return_sock()
    client_address = handle_manager.return_addr()
    old_settings = termios.tcgetattr(sys.stdin)
    server_instants.server_logger.info(f"IP: {client_address} Give it a shell !")

    def resize_handler(signum, frame):
        rows, cols = get_terminal_size(sys.stdin.fileno())
        set_pty_winsize(master_fd, rows, cols)

    try:
        tty.setraw(sys.stdin.fileno())

        master_fd, slave_fd = pty.openpty()

        # Sync terminal size
        rows, cols = get_terminal_size(sys.stdin.fileno())
        set_pty_winsize(slave_fd, rows, cols)

        # Set term so nano/vim/htop work correct มั้งครับ
        env = os.environ.copy()
        env["TERM"] = "xterm-256color"

        shell = subprocess.Popen(
            ["/bin/bash"],
            preexec_fn=os.setsid,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            close_fds=True
        )

        os.close(slave_fd)

        # Listen for terminal resize
        # signal.signal(signal.SIGWINCH, resize_handler)
        buffer = b''
        while True:
            rlist, _, _ = select.select([client_socket, master_fd], [], [])

            if client_socket in rlist:
                try:
                   data = handle_manager.wait_recv_utf8()
                   if data is None:
                      server_instants.server_logger.warning(f"IP: {client_address} Client Down")
                      break
                   data = data.encode()
                   buffer += data
                   server_instants.server_logger.info(f"IP: {client_address} executed: {buffer}")
                   buffer2 = buffer.split(b'\n')
                   for msg in buffer2:
                       msg = msg.decode()
                       if msg.startswith(as_client.RESIZE.decode()):
                          resize_structure = msg.split(':')
                          rows = int(resize_structure[1])
                          cols = int(resize_structure[2])
                          set_pty_winsize(master_fd, rows, cols)
                       elif msg.startswith(as_client.SHELL.decode()):
                             _shell=msg.split(':')[1]
                             os.write(master_fd, _shell.encode())
                       buffer = b''
                except Exception as e:
                    print(e)
            if master_fd in rlist:
                   data = os.read(master_fd, 1024)
                   if not data:
                      break
                   handle_manager.oshell(data)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        try:
            try:
               handle_manager.bye()
            except Exception as e:
               pass
            try:
               os.close(master_fd)
            except Exception as e:
               pass
            try:
               shell.terminate()
               server_instants.server_logger.info(f"IP: {client_address} Shell terminated")
            except Exception as e:
               server_instants.server_logger.warning(f"IP: {client_address} Failed to terminate shell [WARN: {e}]")
            try:
               if client_socket.fileno() != -1:
                  client_socket.close()
                  server_instants.server_logger.info(f"IP: {client_address} Disconnected this client {client_address}")
            except Exception as e:
              server_instants.server_logger.error(f"IP: {client_address} Failed to disconnect [ERROR: {e}]")
        except:
            pass
