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
        self.use_wormhole = config.getint("server", "use_wormhole")
        self.wormhole_entry_point_host = config.get("wormhole-config", "wormhole_entry_point_host")
        self.wormhole_entry_point_port = config.getint("wormhole-config", "wormhole_entry_point_port")
        
        self.remote_host = config.get("remote", "host")
        self.remote_port = config.getint("remote", "port")
        self.remote_max_retries = config.getint("remote", "max_retries")
        self.remote_timeout = config.getint("remote", "timeout")
        self.remote_password = config.get("remote", "password")
        self.remote_wormhole_ticket = config.get("remote-wormhole", "wormhole_ticket")
        self.remote_wormhole_timeout = config.get("remote-wormhole", "timeout")
        self.remote_buffer_size = config.getint("remote", "buffer_size")
        self.remote_max_message_age = config.getint("remote", "max_message_age")