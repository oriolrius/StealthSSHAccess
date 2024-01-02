"""
Network Port Management and Packet Sniffing

This module provides functionality for monitoring and managing network traffic,
specifically targeting the opening and closing of ports based on certain network
conditions. It uses iptables for managing port rules and Scapy for sniffing network
packets. The script monitors specified ports, opens them for certain IP addresses
based on packet data, and maintains a record of these actions.

The script's behavior can be configured through environment variables, allowing
the specification of network interfaces, IP addresses, and ports to monitor. It
also handles logging and persistence of port timer data using a pickle file.

Functions:
- load_timers: Loads timer data from a pickle file.
- update_timers: Updates and saves the timer data to a pickle file.
- open_port: Opens a port for a specific IP address.
- process_packet: Processes each sniffed packet and takes action based on its content.
- ensure_drop_rules: Ensures iptables DROP rules are set for specified ports.
- run_cmd: Executes a system command.

Global Variables:
- LOGLEVEL, iface, iface_ip, port_to_monitor, ports_to_open, filter_expr, PICKLE_FILE, ip_timers

Usage:
The script can be executed as a standalone Python script. Ensure that the required
environment variables are set before running.

Example:
    $ python this_script.py

This module requires external libraries: Scapy, os, logging, time, pickle, subprocess.
"""
import time
from ssh_port_manager import (
    ip_timers,
    load_timers,
    iface,
    iface_ip,
    update_timers,
    ensure_drop_rules,
    run_cmd,
    logger,
    ports_to_open,
    port_to_monitor,
)
from scapy.all import sniff, TCP, IP

# logger.debug show all global variables
logger.debug(f"iface: {iface}")
logger.debug(f"iface_ip: {iface_ip}")
logger.debug(f"port_to_monitor: {port_to_monitor}")
logger.debug(f"ports_to_open: {ports_to_open}")


def process_packet(packet):
    """
    Processes a network packet to check for specific TCP flags and takes action.

    This function examines a given network packet to determine if it contains a TCP
    layer with specific flags (specifically, the 'SYN' flag, indicated by "S"). If such
    a packet is found, and if its destination port is the port we're monitoring
    (`port_to_monitor`), it triggers an action to open the port.

    Parameters:
    packet: A network packet object, expected to contain IP and TCP layers.

    Side Effects:
        - Calls `open_port` function with the source IP and destination port of the packet
          if the packet meets the specified criteria.

    Returns:
    None
    """
    if packet.haslayer(TCP) and (packet[TCP].flags == "S"):
        src_ip = packet[IP].src
        #dst_port = packet[TCP].dport
        for port in ports_to_open:
            open_port(src_ip, port)


def open_port(ip, port):
    """
    Opens a specified port for a given IP address using iptables.

    This function checks if an ACCEPT rule for a specific IP and port combination
    already exists in iptables. If not, it adds this rule. It uses iptables with
    the mangle table for managing these rules. The function also logs the action
    taken and updates the `ip_timers` dictionary to keep track of the time when
    the port was opened for the given IP.

    Parameters:
    ip (str): The IP address for which the port needs to be opened.
    port (int): The port number to be opened for the given IP address.

    Side Effects:
        - Executes iptables commands to add ACCEPT rules.
        - Updates the global `ip_timers` dictionary.
        - Logs actions to the logger.

    Returns:
    None
    """
    base_cmd = "/sbin/iptables -t mangle"
    rule_check = (
        f"{base_cmd} -C PREROUTING -i {iface} -d {iface_ip} "
        f"-p tcp --dport {port} -s {ip} -j ACCEPT"
    )
    rule_add = (
        f"{base_cmd} -I PREROUTING -i {iface} -d {iface_ip} "
        f"-p tcp --dport {port} -s {ip} -j ACCEPT"
    )

    # Open the port for the given IP if it's not already open
    if run_cmd(rule_check) == 0:
        logger.debug(f"Port: {port} already open for source IP address: {ip}")
    else:
        run_cmd(rule_add)
        logger.info(f"Port {port} opened for IP: {ip}")
    # Set the timer for this IP and port
    if ip not in ip_timers:
        ip_timers[ip] = {}
    ip_timers[ip][port] = time.time()
    update_timers()


if __name__ == "__main__":
    # Ensure default behaviour
    ensure_drop_rules(port_to_monitor)
    for p in ports_to_open:
        ensure_drop_rules(p)
    # load old timers
    ip_timers = load_timers()
    # Capturing traffic
    sniff(
        filter=f"tcp port {port_to_monitor}", iface=iface, prn=process_packet, store=0
    )
