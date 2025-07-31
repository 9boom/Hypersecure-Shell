#!/usr/bin/env python3
import logging
import protocol
import sys
# a = append
# w = write
# Configure logging
loggercfg = logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] - %(levelname)s - %(message)s',
        handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('outputs/server.log', mode='a')]
)
server_logger = logging.getLogger(loggercfg)
client_logger = server_logger
if __name__ == '__main__':
   try:
      if len(sys.argv) > 1:
         if sys.argv[1] == 'server':
            s = protocol.HSSServer(HOST='172.19.68.67',PORT=8822,MAX_CLIENTS=2, SERVER_LOGGER=server_logger)
            s.bind()
         elif sys.argv[1] == 'remote':
            c = protocol.HSSClient(HOST='192.168.43.21',PORT=8822,CLIENT_LOGGER=client_logger)
            c.connect()
      else:
            pass
   except Exception as e:
          print(f"Error during parse arguments: {e}")
