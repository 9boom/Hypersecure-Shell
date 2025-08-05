import protocol
import configparser

class Config:
    def __init__(self, config_path):
        config = configparser.ConfigParser()
        config.read(config_path)

        self.use_external_logs = config.getint("logger", "use_external_logs")
        self.logger_server = config.get("logger", "logger_server")
        self.logger_port = config.getint("logger", "logger_port")
        
        self.host = config.get("server", "host")
        self.port = config.getint("server", "port")
        self.max_clients = config.getint("server", "max_connections")
        self.timeout = config.getint("server", "timeout")
        self.time_sleep_before_encrypt = config.getint("server", "time_sleep_before_encrypt")
        self.time_sleep_before_disconnected_from_kick = config.getint("server", "time_sleep_before_disconnected_from_kick")
        self.max_message_age = config.getint("server", "max_message_age")
        self.buffer_size = config.getint("server", "buffer_size")
        self.use_password = config.getint("server", "use_password")
        self.password_to_login = config.get("server", "password_to_login")
        self.use_ZKP = config.getint("server", "use_ZKP")
        self.ZKP_password = config.get("server", "ZKP_password")
        self.use_wormhole = config.getint("server", "use_wormhole")
        self.wormhole_entry_point_host = config.get("server", "wormhole_entry_point_host")
        self.wormhole_entry_point_port = config.getint("server", "wormhole_entry_point_port")
        self.wormhole_entry_point_barrier = config.get("server", "wormhole_entry_point_barrier")
        
        self.remote_host = config.get("remote", "host")
        self.remote_port = config.getint("remote", "port")
        self.remote_max_retries = config.getint("remote", "max_retries")
        self.remote_timeout = config.getint("remote", "timeout")
        self.remote_password = config.get("remote", "password")
        self.remote_ZKP_password = config.get("remote", "ZKP_password")
        self.remote_wormhole_password = config.get("remote", "wormhole_password")
        self.remote_buffer_size = config.getint("remote", "buffer_size")
        self.remote_max_message_age = config.getint("remote", "max_message_age")
        
class ServerSetup():
    def __init__(self,logger=None):
        self.logger = logger    
        self.config = Config('security.ini')
    def launch(self):
        gg = protocol.HSSServer(
            HOST=self.config.host,
            PORT=self.config.port,
            MAX_CLIENTS=self.config.max_clients,
            SERVER_LOGGER=self.logger,
            TIMEOUT=self.config.timeout,
            TIME_SLEEP_BEFORE_ENCRYPT=self.config.time_sleep_before_encrypt,
            TIME_SLEEP_BEFORE_DISCONNECTED_FROM_KICK=self.config.time_sleep_before_disconnected_from_kick,
            MAX_MESSAGE_AGE=self.config.max_message_age,
            BUFFER_SIZE=self.config.buffer_size,
            USE_PASSWORD=self.config.use_password,
            PASSWORD_TO_LOGIN=self.config.password_to_login,
            USE_ZKP=self.config.use_ZKP,
            ZKP_PASSWORD=self.config.ZKP_password,
            USE_WORMHOLE=self.config.use_wormhole,
            WORMHOLE_ENTRY_POINT_HOST=self.config.wormhole_entry_point_host,
            WORMHOLE_ENTRY_POINT_PORT=self.config.wormhole_entry_point_port,
            WORMHOLE_ENTRY_POINT_BARRIER=self.config.wormhole_entry_point_barrier
        )
        gg.bind()
class ClientSetup():
    def __init__(self,logger=None):
        self.logger = logger
        self.config = Config('security.ini')
    def launch(self):
        gg = protocol.HSSClient(
            HOST=self.config.remote_host,
            PORT=self.config.remote_port,
            CLIENT_LOGGER=self.logger,
            TIMEOUT=self.config.remote_timeout,
            MAX_RETRIES=self.config.remote_max_retries,
            PASSWORD=self.config.remote_password,
            ZKP_PASSWORD=self.config.remote_ZKP_password,
            WORMHOLE_PASSWORD=self.config.remote_wormhole_password,
            BUFFER_SIZE=self.config.remote_buffer_size
        )
        gg.connect()