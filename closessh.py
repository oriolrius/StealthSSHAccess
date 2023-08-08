import os
import logging
import psutil
import time
import pickle
import time
from openssh import update_timers, load_timers

# Debug
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)
logger.debug(f'LOGLEVEL = {LOGLEVEL}')

# Configuration
TIMEOUT = int(os.getenv('TIMEOUT')) or 600 # Timeout in seconds
WAIT_LOOP = int(os.getenv('TIMEOUT')) or 60 # 1'
iface = os.getenv('IFACE') or "eth0"
iface_ip = os.getenv("IFACE_IP") or "172.19.0.2"
port_to_monitor = int(os.getenv('PORT_TO_MONITOR')) or 55888
filter_expr = f"tcp port {port_to_monitor}"
port_to_open = int(os.getenv('PORT_TO_OPEN')) or 55222
PICKLE_FILE = '/data/' + os.getenv('PICKLE_FILE') or 'timers.pkl'

# Program data
ip_timers = {}

def check_and_close_ports(ip):
    # Check if there is an active connection from this IP
    for connection in psutil.net_connections(kind='inet'):
        # logger.debug(f'connection: {connection}')
        comparison_results = (
            connection.laddr.port == port_to_open,
            connection.status == 'ESTABLISHED',
            connection.raddr and connection.raddr[0] == ip  # check if raddr is not empty and access the IP address from the tuple
        )
        if all(comparison_results):
            logger.info(f'SSH connection detected from triggering IP {ip}, resetting timer to check again later')
            ip_timers[ip] = time.time()
            return

    # Check if it's unsed for more than TIMEOUT
    ttl = time.time() - ip_timers[ip]
    logger.debug(f"Calculating Time-to-live (TTL) for IP {ip}. TTL: {ttl}, TIMEOUT: {TIMEOUT}.")
    if ttl > TIMEOUT:
        close_port(ip)

def close_port(ip):
    # If no active connections are found, remove the ACCEPT entry for this IP
    os.system(f'/sbin/iptables -D INPUT -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT')
    logger.info(f'Removed ACCEPT rule for IP: {ip}')
    try:
        del ip_timers[ip]
        update_timers()
    except KeyError:
        pass

if __name__ == "__main__":
    while True:
        ip_timers = load_timers()
        logger.info(ip_timers)
        for ip in dict(ip_timers): # make a copy for iterating, avoid problems removing items of the dict
            logger.debug(f'check_and_close_ports: {ip}')
            check_and_close_ports(ip)
        time.sleep(WAIT_LOOP) # Sleep for a short time to prevent busy-waiting