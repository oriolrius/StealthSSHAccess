import os
import sys
import logging
import psutil
from scapy.all import *
import time
import pickle
import subprocess

# Debug
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger("openssh")
logger.debug(f'LOGLEVEL = {LOGLEVEL}')

# Configuration
iface = os.getenv('IFACE') or "eth0"
iface_ip = os.getenv("IFACE_IP") or "172.19.0.2"
port_to_monitor = os.getenv('PORT_TO_MONITOR') or 55888
port_to_monitor = int(port_to_monitor)
filter_expr = f"tcp port {port_to_monitor}"
port_to_open = os.getenv('PORT_TO_OPEN') or 55222
port_to_open = int(port_to_open)
PICKLE_FILE = '/data/' + ( os.getenv('PICKLE_FILE') or 'timers.pkl')

# Program data
ip_timers = {} # This will store the timers for each triggering IP

def load_timers():
    # Load pickled data from file
    if os.path.exists(PICKLE_FILE):
      try:
        with open(PICKLE_FILE, 'rb') as file:
            ip_timers = pickle.load(file)
      except pickle.UnpicklingError as e:
        logger.debug(f"Error loading pickle file: {PICKLE_FILE} - {e}")
        update_timers()
    else:
        update_timers()
    logger.info(f"Loaded pickle file: {PICKLE_FILE} - ip_timers: {ip_timers}")
    return ip_timers

def update_timers():
    with open(PICKLE_FILE, 'wb') as file:
        pickle.dump(ip_timers, file)
    logger.info(f"Updated pickle file: {PICKLE_FILE} - ip_timers: {ip_timers}")
    
    return ip_timers

def open_port(ip):
    # Open the port for the given IP if it's not already open
    if run_cmd(f'/sbin/iptables -t mangle -C PREROUTING -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT') == 0:
        logger.debug(f'Port: {port_to_open} already open for source IP address: {ip}')
    else:
        run_cmd(f'/sbin/iptables -t mangle -I PREROUTING -i {iface} -d {iface_ip} -p tcp --dport {port_to_open} -s {ip} -j ACCEPT')
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
    if  run_cmd(f'/sbin/iptables -t mangle -C PREROUTING -i {iface} -d {iface_ip} -p tcp --dport {port} -j DROP') != 0:
        run_cmd(f'/sbin/iptables -t mangle -I PREROUTING -i {iface} -d {iface_ip} -p tcp --dport {port} -j DROP')
        logger.info(f'DROP rule added for port {port}')
    else:
        logger.info(f'DROP rule already existing for port {port}')

def run_cmd(cmd):
    logger.debug(f'Running command: {cmd}')
    #exit_code = subprocess.run(cmd.split(' '), check=True)
    try:
        subprocess.run(cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        exit_code = 0  # Rule exists
    except subprocess.CalledProcessError:
        exit_code = 1  # Rule doesn't exist
    logger.debug(f'Exit code: {exit_code}')
    return exit_code

if __name__ == "__main__":
    # Ensure default behaviour
    ensure_drop_rules(port_to_monitor)
    ensure_drop_rules(port_to_open)
    # load old timers
    ip_timers = load_timers()
    # Capturing traffic
    sniff(filter=filter_expr, iface=iface, prn=process_packet, store=0)
