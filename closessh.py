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
import time
import psutil
from ssh_port_manager import (
    load_timers,
    iface,
    iface_ip,
    ip_timers,
    update_timers,
    run_cmd,
    logger,
    ports_to_open,
    TIMEOUT,
    WAIT_LOOP
    )

def check_and_close_ports(ip):
    """
    Checks each open port for a given IP address and closes it if inactive.

    This function iterates through all ports in `ports_to_open` and checks for any
    active connections from the given IP address. If a port has been inactive for
    longer than the specified TIMEOUT, it triggers the port to close.

    Parameters:
    ip (str): The IP address for which to check open ports.
    """
    for port in list(ip_timers[ip]):
        logger.debug(f"Checking if {ip}:{port} is active.")
        # Check if there is an active connection from this IP
        for connection in psutil.net_connections(kind="inet"):
            comparison_results = (
                connection.laddr.port == port,
                connection.status == "ESTABLISHED",
                connection.raddr and connection.raddr[0] == ip
            )
            if all(comparison_results):
                logger.info(
                  f"TCP connection detected from {ip}:{port}, resetting timer "
                  f"to check again later."
                )
                for p in ports_to_open:
                    ip_timers[ip][p] = time.time()
                update_timers()
                return

        # Check if it's unused for more than TIMEOUT
        try:
            ttl = int(time.time() - ip_timers[ip][port])
        except KeyError:
            logger.debug(f"KeyError: {ip}:{port} - closing port.")
            close_port(ip, port)
            continue
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
        f"/sbin/iptables -D INPUT -i {iface} -d {iface_ip} "
        f"-p tcp --dport {port} -s {ip} -j ACCEPT"
    )
    run_cmd(iptables_cmd)
    logger.info(f"Removed ACCEPT rule for IP: {ip} and port: {port}")
    try:
        del ip_timers[ip][port]
        update_timers()
    except KeyError:
        logger.warning(f"KeyError: {ip}:{port} - removing IP:PORT from ip_timers.")


if __name__ == "__main__":
    while True:
        ip_timers = load_timers()
        logger.info(ip_timers)
        for the_ip in list(ip_timers):
            logger.debug(f"check_and_close_ports: {the_ip}")
            check_and_close_ports(the_ip)
        time.sleep(WAIT_LOOP)
