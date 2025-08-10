import protocol
from loader import Config
from wormhole.wormhole import Wormhole
from wormhole.ticket import Ticket

class ServerSetup():
    def __init__(self,logger=None):
        self.logger = logger
        self.config = Config('security.ini')
    def launch(self):
        if self.config.use_wormhole:
            ticket = Ticket(self.logger)
            wormhole = Wormhole(host=self.config.wormhole_entry_point_host,port=self.config.wormhole_entry_point_port, logger=self.logger, ticket=ticket )
            try:
               wormhole.run()
               if wormhole.check():
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
            ZKP_NUM_ROUND = self.config.ZKP_num_round,
            USE_WORMHOLE=self.config.use_wormhole,
            WORMHOLE_ENTRY_POINT_HOST=self.config.wormhole_entry_point_host,
            WORMHOLE_ENTRY_POINT_PORT=self.config.wormhole_entry_point_port
            )
                   gg.bind()
            except (Exception, KeyboardInterrupt) as e:
                print('Wormhole error. Let me calling albert einstein...')
                e = str(e)
                if not e.strip():
                    print('Albert einstein has no idea I will shutdown with no reason.')
                else:
                    self.logger.error(f"[WORMHOLE] {e}")
                    print(f"[WORMHOLE] {e}")
        elif not self.config.use_wormhole:
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
            ZKP_NUM_ROUND = self.config.ZKP_num_round,
            USE_WORMHOLE=self.config.use_wormhole,
            WORMHOLE_ENTRY_POINT_HOST=self.config.wormhole_entry_point_host,
            WORMHOLE_ENTRY_POINT_PORT=self.config.wormhole_entry_point_port
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
            BUFFER_SIZE=self.config.remote_buffer_size
        )
        gg.connect()
