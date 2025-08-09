#!/usr/bin/env python3
import logging
import logging.handlers
import protocol
import sys
import time
from datetime import datetime, timezone
import os
import launcher
from wormhole.ticket import Ticket
from wormhole.spaceship import Spaceship
# a = append
# w = write
# 
# Configure logging
def setup_logger(name: str, log_file: str, level = logging.INFO):
   class UTCFormatter(logging.Formatter):
      converter = time.gmtime()

      def formatTime(self, record, datefmt = None):
         utc_time = datetime.fromtimestamp(record.created, tz=timezone.utc)
         if datefmt:
            return utc_time.strftime(datefmt)
         return utc_time.isoformat(timespec="milliseconds")
   if not os.path.exists(log_file):
      os.makedirs(os.path.dirname(log_file), exist_ok= True)
   formatter = UTCFormatter(
         fmt='[%(asctime)s.%(msecs)03dZ] - %(levelname)s - %(message)s',
         datefmt="%Y-%m-%dT%H:%M:%S"
   )
   handler = logging.handlers.RotatingFileHandler(
         filename=log_file,
         maxBytes = 5 *1024*1024,
         backupCount = 1,
         encoding = 'utf-8'
      )
   handler.setFormatter(formatter)

   logger = logging.getLogger(name)
   logger.setLevel(level)
   logger.addHandler(handler)

   logger.propagate = False

   return logger
server_logger = setup_logger('server', 'outputs/logs/server.log')
client_logger = setup_logger("client", 'outputs/logs/client.log')
if __name__ == '__main__':
   try:
      if len(sys.argv) > 1:
         if sys.argv[1] == 'server':
            launcher.ServerSetup(logger=server_logger).launch()
         elif sys.argv[1] == 'remote':
            launcher.ClientSetup(logger=client_logger).launch()
         elif sys.argv[1] == 'logger':
            launcher.ClientSetup(logger=server_logger).launch()
         elif sys.argv[1] == "wormhole-config":
            try:
               ticket = Ticket(server_logger)
               ticket.setup()
            except KeyboardInterrupt:
               pass
         elif sys.argv[1] == "wormhole-remote":
            spaceship = Spaceship(logger=client_logger,ticket=Ticket(client_logger))
            print(spaceship.shoot())
      else:
            pass
   except Exception as e:
         print(f"Error during parse arguments: {e}")