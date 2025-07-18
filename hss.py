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
        logging.FileHandler('server.log', mode='a')]
)
logger = logging.getLogger('server')

if __name__ == '__main__':
   try:
      if len(sys.argv) > 1:
         if sys.argv[1] == 'server':
            s = protocol.HSSServer(HOST='127.0.0.1',PORT=8822,MAX_CLIENTS=2, SERVER_LOGGER=logger)
            s.bind()
         elif sys.argv[1] == 'remote':
            c = protocol.HSSClient(HOST='127.0.0.1',PORT=8822,CLIENT_LOGGER=logger)
            c.connect()
      else:
            pass
   except Exception as e:
          logger.error(f"Error during parse arguments: {e}")
