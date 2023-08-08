import os
import sys
from scapy.all import *
import logging
import psutil
import asyncio

# Debug
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)
logger.debug(f'LOGLEVEL = {LOGLEVEL}')

# Configuration
iface = os.getenv('IFACE') or "eth0"
iface_ip = os.getenv("IFACE_IP") or "172.19.0.2"
port_to_monitor = int(os.getenv('PORT_TO_MONITOR')) or 55888
filter_expr = f"tcp port {port_to_monitor}"
port_to_open = int(os.getenv('PORT_TO_OPEN')) or 55222
TIMEOUT = 5  # Timeout in seconds

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
        ip_timers[ip].cancel()
    ip_timers[ip] = asyncio.get_event_loop().call_later(TIMEOUT, check_and_close_port, ip)
    
def check_and_close_port(ip):
    # Check if there is an active connection from this IP
    for connection in psutil.net_connections(kind='inet'):
        comparison_results = (
            connection.laddr.port == port_to_open,
            connection.status == 'ESTABLISHED',
            connection.raddr and connection.raddr[0] == ip  # check if raddr is not empty and access the IP address from the tuple
        )

        if all(comparison_results):
            logger.info(f'SSH connection detected from triggering IP {ip}, resetting timer to check again later')
            ip_timers[ip].cancel()
            ip_timers[ip] = asyncio.get_event_loop().call_later(TIMEOUT, check_and_close_port, ip)
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
        logger.debug(ip_timers)
        pass

def process_packet(packet):
  if packet.haslayer(TCP) and (packet[TCP].flags == 'S'):
    src_ip = packet[IP].src
    # Open the port for this IP
    open_port(src_ip)

async def sniff_packets():
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, lambda: sniff(filter=filter_expr, iface=iface, prn=lambda pkt: process_packet(pkt), store=0))


if __name__ == "__main__":
  loop = asyncio.get_event_loop()    
  loop.create_task(sniff_packets())
  loop.run_forever()
