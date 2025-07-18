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

def activate(connection,client_address,server_instants):
    old_settings = termios.tcgetattr(sys.stdin)

    def resize_handler(signum, frame):
        rows, cols = get_terminal_size(sys.stdin.fileno())
        set_pty_winsize(master_fd, rows, cols)

    try:
        tty.setraw(sys.stdin.fileno())

        master_fd, slave_fd = pty.openpty()

        # Sync terminal size
        rows, cols = get_terminal_size(sys.stdin.fileno())
        set_pty_winsize(slave_fd, rows, cols)

        # Set term so nano/vim/htop work correctly มั้งครับ
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
            rlist, _, _ = select.select([connection, master_fd], [], [])

            if connection in rlist:
                try:
                   data = connection.recv(1024)
                   if not data:
                      server_instants.server_logger.warning(f"IP: {client_address} Client Down")
                      break
                   buffer += data
                   server_instants.server_logger.info(f"IP: {client_address} executed: {buffer}")
                   special_cmd = buffer.split(b'\n')
                   for sc in special_cmd:
                       sc = sc.decode('utf-8')
                       if sc.startswith("SHELL_RESIZE_REQUEST"):
                          cmd_splits = sc.split(":")
                          rows = int(cmd_splits[1])
                          cols = int(cmd_splits[2])
                          set_pty_winsize(master_fd,rows,cols)
                       else:
                          os.write(master_fd, sc.encode())
                          buffer = b''
                except Exception as e:
                    print(e)
            if master_fd in rlist:
                   data = os.read(master_fd, 1024)
                   if not data:
                      break
                   connection.sendall(data)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        try:
            try:
               connection.sendall("SAY_BYE\n".encode())
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
               if connection.fileno() != -1:
                  connection.close()
                  server_instants.server_logger.info(f"IP: {client_address} Disconnected this client connection")
            except Exception as e:
              server_instants.server_logger.error(f"IP: {client_address} Failed to disconnect [ERROR: {e}]")
        except:
            pass
