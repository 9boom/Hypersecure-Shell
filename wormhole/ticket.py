import random
from pathlib import Path
import time
from config import Config
import os

class Ticket():
    def __init__(self, logger):
        self.path_to_store = Path('outputs/wormhole')
        self.ticket_path = self.path_to_store / "spaceship.ticket"
        self.config = Config('security.ini')
        self.ticket = ""
        self.logger = logger
    def setup(self):
        self.path_to_store.mkdir(parents=True, exist_ok=True)
        if self.path_to_store.exists() and self.ticket_path.exists():
            while True:
                q = str(input("[The ticket has already been created. Do you want to delete it and create a new one?][yn]: "))
                if q.lower().strip() == 'y':
                    try:
                        self.make() 
                    except Exception as e:
                        self.logger.error(f"Failed to create new ticket file [ERROR {e}]")
                        print(f"Failed to create new ticket file [ERROR: {e}]")
                    break
                elif q.lower().strip() == 'n':
                    break
                else:
                    self.logger.warning(f"You type a wrong key. Try again [WARNING : {q}]")
                    print("You type a wrong key. try again")
        else:
            self.make()            
    def make(self):
        # TO OUTPUTS
        with open(self.ticket_path, 'wb') as f:
            data = self.generate_ticket().encode()
            f.write(data)
            f.close()
            # TO_CONFIG_SERVER
            Path('.config/wormhole').mkdir(parents=True, exist_ok=True)
            with open('.config/wormhole/spaceship.ticket', 'wb') as f:
                f.write(data)
                f.close()
    def load(self):
        try:
            with open(self.config.remote_wormhole_ticket) as f:
                data = f.read()
                f.close()
        except Exception as e:
            self.logger.error(f'Failed to load ticket file [ERROR: {e}]')
            print(f"Failed to load ticket, Please set correct 'wormhole_ticket' path in security.ini")
            return None
        return str(data)
    def load_for_server(self):
        try:
            with open('.config/wormhole/spaceship.ticket') as f:
                data = f.read()
                f.close()
            return data
        except Exception as e:
            print("Please run 'python3 hss.py wormhole-config' first ")
            self.logger.error(f"Failed to load ticket [ERROR: {e}]")
            return None
    def generate_ticket(self):
        print("Generating a strong ticket...")
        data = str(self.config.wormhole_entry_point_host) + '%' + str(self.config.wormhole_entry_point_port) + '%' + str(time.time()) + str(time.asctime()) + str(random.randint(9999999999,99999999999)) + 'true_key' + str(random.randint(9999999999,99999999999))
        time.sleep(random.randint(0,7))
        print("This may take a few seconds....")
        for i in range(random.randint(5,25)):
            data += str(time.time())
            time.sleep(random.randint(0,2))
        print("Created to outputs/wormhole/spaceship.ticket ")
        print("Share this file to your computer that you want to run it as remote. This is a important secret file to unlock wormhole feature if you set it on on this computer.")
        return str(data)