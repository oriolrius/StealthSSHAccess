"""
Close SSH Ports Module

This module periodically checks and closes open SSH ports that are no longer in use. 
It's designed to work in conjunction with the openssh.py script, which opens ports based on certain 
network conditions. 
This script uses the iptables command to manage port rules and psutil for inspecting active network 
connections.

The script's behavior can be configured through environment variables, allowing the specification of 
network interfaces, IP addresses, and ports to monitor. 
It also handles logging and updating the timer data using functions imported from the openssh 
module.

Functions:
- check_and_close_ports: Checks for active connections on open ports and closes them if inactive.
- close_port: Closes an open port for a specific IP address.

Usage:
The script runs in an infinite loop, periodically checking for ports to close. 
Ensure that the required environment variables are set before running.

Example:
    $ python closessh.py
"""

import os
import logging
import time
import psutil
from openssh import update_timers, load_timers, run_cmd

# Debug
LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger("closessh")
logger.debug(f"LOGLEVEL = {LOGLEVEL}")

# Configuration
TIMEOUT = int(os.getenv("TIMEOUT", 600))
WAIT_LOOP = int(os.getenv("WAIT_LOOP", 60))
iface = os.getenv("IFACE", "eth0")
iface_ip = os.getenv("IFACE_IP", "172.19.0.2")
port_to_monitor = int(os.getenv("PORT_TO_MONITOR", 55888))
ports_to_open = [int(port) for port in os.getenv("PORTS_TO_OPEN", "55222").split(",")]
PICKLE_FILE = "/data/" + os.getenv("PICKLE_FILE", "timers.pkl")

# Program data
ip_timers = {}

def check_and_close_ports(ip):
    """
    Checks each open port for a given IP address and closes it if inactive.

    This function iterates through all ports in `ports_to_open` and checks for any
    active connections from the given IP address. If a port has been inactive for
    longer than the specified TIMEOUT, it triggers the port to close.

    Parameters:
    ip (str): The IP address for which to check open ports.
    """
    for port in ports_to_open:
        # Check if there is an active connection from this IP
        for connection in psutil.net_connections(kind="inet"):
            comparison_results = (
                connection.laddr.port == port,
                connection.status == "ESTABLISHED",
                connection.raddr and connection.raddr[0] == ip
            )
            if all(comparison_results):
                logger.info(
                  "SSH connection detected from IP {}, resetting timer "
                  "to check again later".format(ip)
                )
                ip_timers[ip] = time.time()
                return

        # Check if it's unused for more than TIMEOUT
        ttl = time.time() - ip_timers.get(ip, 0)
        logger.debug(f"Calculating Time-to-live (TTL) for IP {ip}. TTL: {ttl}, TIMEOUT: {TIMEOUT}.")
        if ttl > TIMEOUT:
            close_port(ip, port)

def close_port(ip, port):
    """
    Closes a specified port for a given IP address.

    This function removes the ACCEPT rule from iptables for a specific IP and port
    combination, effectively closing the port for that IP address. It updates the
    `ip_timers` to reflect this change.

    Parameters:
    ip (str): The IP address for which the port needs to be closed.
    port (int): The port number to be closed for the given IP address.
    """
    iptables_cmd = (
        f"/sbin/iptables -t mangle -D PREROUTING -i {iface} -d {iface_ip} "
        f"-p tcp --dport {port} -s {ip} -j ACCEPT"
    )
    run_cmd(iptables_cmd)
    logger.info(f"Removed ACCEPT rule for IP: {ip} and port: {port}")
    try:
        del ip_timers[ip]
        update_timers()
    except KeyError:
        pass

if __name__ == "__main__":
    while True:
        ip_timers = load_timers()
        logger.info(f"Current IP Timers: {ip_timers}")
        for ip in list(ip_timers):
            logger.debug(f"Checking and potentially closing ports for IP: {ip}")
            check_and_close_ports(ip)
        time.sleep(WAIT_LOOP)  # Sleep to prevent busy-waiting
