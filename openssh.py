import os
import sys
from scapy.all import *
import logging
import psutil
from threading import Timer
import signal

# Debug
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger('traffic_monitor')
logger.debug(f'LOGLEVEL = {LOGLEVEL}')

# Configuration
iface = os.getenv('IFACE') or "eth0"
iface_ip = os.getenv("IFACE_IP") or "172.19.0.2"
port_to_monitor = int(os.getenv('PORT_TO_MONITOR') or "55888")
filter_expr = f"tcp port {port_to_monitor}"
port_to_open = int(os.getenv('PORT_TO_OPEN') or port_to_open)
TIMEOUT = 60

# Program data
ip_timers = {} # This will store timers for each triggering IP

def open_port(ip):
    # Open the port for the given IP if it's not already open
    if os.system(f'/sbin/iptables -C INPUT -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT') == 0:
        return

    os.system(f'/sbin/iptables -I INPUT -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT')
    logger.info(f'Port {port_to_open} opened for IP: {ip}')

    # Start or reset the timer for this IP
    if ip in ip_timers:
        ip_timers[ip].reset()
    else:
        ip_timers[ip] = RepeatingTimer(TIMEOUT, lambda: check_and_close_port(ip))
    
def check_and_close_port(ip):
    # Check if there is an active connection from this IP
    for connection in psutil.net_connections(kind='inet'):
        comparison_results = (
            connection.laddr.port == port_to_open,
            connection.status == 'ESTABLISHED',
            connection.raddr and connection.raddr[0] == ip  # check if raddr is not empty and access the IP address from the tuple
        )
        # try:
        #     debug_msg = f'Comparing local port {connection.laddr.port} to {port_to_open}: {comparison_results[0]}, ' \
        #                 f'status to "ESTABLISHED": {comparison_results[1]}, ' \
        #                 f'remote IP {connection.raddr[0]} to {ip}: {comparison_results[2]}'
        # except IndexError:
        #     debug_msg = f'Error retrieving remote IP for connection: {connection}'  # Error message when raddr tuple is empty
        # logger.debug(debug_msg)
        if all(comparison_results):
            logger.info(f'SSH connection detected from triggering IP {ip}, resetting timer to check again later')
            ip_timers[ip].reset()
            return
    close_port(ip)

def close_port(ip):
    # If no active connections are found, remove the ACCEPT entry for this IP
    os.system(f'/sbin/iptables -D INPUT -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT')
    logger.info(f'Removed ACCEPT rule for IP: {ip}')
    try:
        ip_timers[ip].cancel()
        del ip_timers[ip]
    except KeyError:
        pass

# def process_packet(packet):
#     if packet.haslayer(TCP) and packet.haslayer(Raw):
#         # Check if it's an HTTP GET request with the specific URI
#         if b'GET /openssh' in packet[Raw].load:
#             src_ip = packet[IP].src
#             # Open the port for this IP
#             open_port(src_ip)

def process_packet(packet):
    if packet.haslayer(TCP) and (packet[TCP].flags == 'S'):
        src_ip = packet[IP].src
        # Open the port for this IP
        open_port(src_ip)

class RepeatingTimer:
    def __init__(self, interval, function):
        self._timer = None
        self.interval = interval
        self.function = function
        self.reset()

    def _run(self):
        self.function()
        self._timer = Timer(self.interval, self._run)
        self._timer.start()

    def reset(self):
        if self._timer:
            self._timer.cancel()
        self._timer = Timer(self.interval, self._run)
        self._timer.start()

    def cancel(self):
        if self._timer:
            self._timer.cancel()

def ensure_drop_rules(port):
    # Check if the DROP rule for port {port_to_open} exists, and if not, add it
    drop_rule = f'/sbin/iptables -C INPUT -i {iface} -d {iface_ip} -p tcp --dport {port} -j DROP'
    if os.system(drop_rule) != 0:
        os.system(f'/sbin/iptables -I INPUT -i {iface} -d {iface_ip} -p tcp --dport {port} -j DROP')
        logger.info('DROP rule added for port {port_to_open}')

def cleanup(signum, frame):
    logger.info('Received termination signal, cleaning up...')
    for ip, timer in ip_timers.items():
        close_port(ip)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

if __name__ == "__main__":
    ensure_drop_rules(port_to_monitor)
    ensure_drop_rules(port_to_open)
    sniff(filter=filter_expr, prn=process_packet, iface=iface, store=False)
