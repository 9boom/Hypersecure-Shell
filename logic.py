import logging
import sys

data = b'HELLO\nDATA\nGOOD\nMORNING\n'

while b'\n' in data:
      print("...")
      packet, data = data.split(b'\n',1)
      print(packet," ", data)
# a = append
# w = write
# Configure logging
'''loggercfg = logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('hss.log', mode='a')]
)

logger = logging.getLogger(loggercfg)

logger.error("Hi")'''
#logger.error("Yo")
#logger.debug("Broke")
#logger.warning("Are you sure?")
#logger.info("Test")

'''import heapq

g = []
heapq.heappush(g,(0,5,2,"Im"))
heapq.heappush(g,(0,5,1,"Legend"))
heapq.heappush(g,(0,7,3,"Are you?"))

a,b,c,d = g[0]

heapq.heappop(g)

for gi in g:
    print(gi[3])
'''
