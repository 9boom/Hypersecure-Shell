# EasyShell
**EasySH (ezsh)** is an alternative to SSH, written entirely in Python, designed to run without root privileges for remote computer control. 

![server](assets/server.gif)
![client](assets/client.gif)
---

---

## 📦 Installation

**Prerequisites:**

* Python 3+
* `pip`
* Command-line knowledge

**Recommended:** Run inside a Python virtual environment:

```bash
python3 -m venv .hssvenv
source .ezsh_venv/bin/activate
```

**Steps:**

```bash
# 1. Clone repository
git clone https://github.com/9boom/Hypersecure-Shell.git

# 2. Enter directory
cd Hypersecure-Shell

# 3. Install dependencies
bash install.sh
```

Installation may take several minutes.

---

## ⚙️ Configuration

configured via `security.ini`.

```ini
# Logger Configuration Section for your Server to store (External logging backup server system)
[bklogger-here]
# Set host for your logging server
logger_server = 0.0.0.0
# Port number
logger_port = 2288
# Chunk size for prevent too large logs data
chunk_size = 1024
# Refresh time per read and send
refresh_time = 1

[bklogger-to]
# IP address of the logging server to backup log to
logger_server_cli = 0.0.0.0
# Port number for the logging server connection
logger_port_cli = 2288
# Output logs location
output_logs = backup.log

# Server Configuration Section
[server]
# IP address or hostname that the HSS server will bind to
host = 0.0.0.0
# Port number that the server will listen on for incoming REMOTE connections
port = 8822
# Maximum number of simultaneous client connections allowed
max_connections = 6
# Connection timeout in seconds before dropping inactive connections
timeout = 15
# Delay in seconds before starting encryption process
time_sleep_before_encrypt = 1
# Delay in seconds before disconnecting a client that has been kicked
time_sleep_before_disconnected_from_kick = 2
# Maximum age in seconds for messages to be considered valid
max_message_age = 30
# Size of the network buffer in bytes for data transmission
buffer_size = 8192
# Enable password authentication (0 = disabled, 1 = enabled)
use_password = 1
# Password required for client login authentication
password_to_login = hackerman007
# Enable Zero-Knowledge Proof authentication (0 = disabled, 1 = enabled)
use_ZKP = 0
# ZKP Num Round Challenge
# WARNNING !!! : For security, do not set this value below 100.
ZKP_num_round = 300
# Enable wormhole connection feature (0 = disabled, 1 = enabled)
use_wormhole = 0

# Remote Server Configuration Section
[remote]
# IP address or hostname of the remote server to connect to
host = 0.0.0.0
# Port number of the remote server
port  = 8822
# Maximum number of connection retry attempts
max_retries = 3
# Connection timeout in seconds for remote connections
timeout = 15
# Password for authenticating with the remote server
# Default : ASK_EVERY_TIME
password = ASK_EVERY_TIME
# Size of the network buffer in bytes for data transmission
buffer_size = 8192
# Maximum age in seconds for messages to be considered valid
max_message_age = 30

# Wormhole configuration for ticket
[wormhole-ticket]
# Entry point IP for wormhole feature
# Set this value for How ticket will remote
wormhole_entry_point_host = 0.0.0.0
# Default : RANDOM_PORT
wormhole_entry_point_port = RANDOM_PORT

# Wormhole spaceship
[wormhole-remote]
# Wormhole ticket for remote wormhole connections
wormhole_ticket = outputs/wormhole/spaceship.ticket
# Space ship timeout
timeout = 15

```

---

### Main Sections

| Section                | Purpose                                                                 |
| ---------------------- | ----------------------------------------------------------------------- |
| **\[server]**          | HSS server configuration. Run this to host and accept connections to allow remote. |
| **\[remote]**          | Connect to a running HSS server to remote.                                        |
| **\[bklogger-here]**   | Back up logs to another server (run separately from main server).       |
| **\[bklogger-to]**     | Pull logs from main server to local machine.                            |
| **\[wormhole-ticket]** | Create a wormhole ticket (explained below).                             |
| **\[wormhole-remote]** | Unlock a wormhole on the target server using a ticket.                  |

---

## 🖥 Usage

Run a section:

```bash
./hss.py <section_name>
```

Example:

```bash
./hss.py wormhole-ticket
```

---

## 🔐 Special Features

### Zero-Knowledge Proof (ZKP)

Set `use_ZKP = 1` in `[server]` to require clients to **prove** they know the password **without sending it**—protecting against eavesdropping.

### Wormhole Mode

Experimental security feature to hide the real HSS server:

* Opens a temporary **random port** (wormhole)
* Requires a valid **ticket** to unlock the real server
* Incorrect tickets result in an abort and block

---

### Wormhole Workflow

**On the server:**

1. Enable wormhole mode:

   ```ini
   use_wormhole = 1
   ```
2. Generate ticket:

   ```bash
   ./hss.py wormhole-ticket
   ```
3. Ticket is saved at `outputs/wormhole/spaceship.ticket`.
4. Share the ticket with the intended client.

**On the client:**

1. Set `wormhole_ticket` in `security.ini` to the ticket path.
2. Unlock wormhole:

   ```bash
   ./hss.py wormhole-remote
   ```
3. If successful:

   ```
   Passed, Go ahead!
   ```
4. Connect:

   ```bash
   ./hss.py remote
   ```

---

## 📜 License

MIT License

---

## ☕ Support the Developer

If you like this project, you can

 [![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/9boom)
