import os
import sys
import logging
import psutil
from scapy.all import *
import time
import pickle
from closessh import 

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
PICKLE_FILE = os.getenv('PICKLE_FILE')) or 'timers.pkl'

# Program data
ip_timers = {} # This will store timers for each triggering IP

def load_timers():
    # Load pickled data from file
    with open(PICKLE_FILE, 'rb') as file:
        ip_timers = pickle.load(file)
    logger.info(f"Loaded pickle file: {PICKLE_FILE} - ip_timers: {ip_timers}")

def update_timers():
    with open(PICKLE_FILE, 'wb') as file:
        pickle.dump(ip_timers, file)
    logger.info(f"Updated pickle file: {PICKLE_FILE} - ip_timers: {ip_timers}")

def open_port(ip):
    # Open the port for the given IP if it's not already open
    if os.system(f'/sbin/iptables -C INPUT -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT') == 0:
        return

    os.system(f'/sbin/iptables -I INPUT -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT')
    logger.info(f'Port {port_to_open} opened for IP: {ip}')

    # Set the timer for this IP
    ip_timers[ip] = time.time()
    update_timers()

def process_packet(packet):
    if packet.haslayer(TCP) and (packet[TCP].flags == 'S'):
        src_ip = packet[IP].src
        open_port(src_ip)

def ensure_drop_rules(port):
    # Check if the DROP rule for port {port_to_open} exists, and if not, add it
    drop_rule = f'/sbin/iptables -C INPUT -i {iface} -d {iface_ip} -p tcp --dport {port} -j DROP'
    if os.system(drop_rule) != 0:
        os.system(f'/sbin/iptables -I INPUT -i {iface} -d {iface_ip} -p tcp --dport {port} -j DROP')
        logger.info('DROP rule added for port {port_to_open}')

if __name__ == "__main__":
    # Ensure default behaviour
    ensure_drop_rules(port_to_monitor)
    ensure_drop_rules(port_to_open)
    # load old timers
    load_timers()
    # Capturing traffic
    sniff(filter=filter_expr, iface=iface, prn=process_packet, store=0)
