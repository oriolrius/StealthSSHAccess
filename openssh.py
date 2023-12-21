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
import os
import logging
import time
import pickle
import subprocess
from scapy.all import sniff, TCP, IP

# Debug
LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger("openssh")
logger.debug(f"LOGLEVEL = {LOGLEVEL}")

# Configuration
iface = os.getenv("IFACE") or "eth0"
iface_ip = os.getenv("IFACE_IP") or "172.19.0.2"
port_to_monitor = int(os.getenv("PORT_TO_MONITOR", "55888"))
ports_to_open = [int(port) for port in os.getenv("PORTS_TO_OPEN", "55222").split(",")]
filter_expr = f"tcp port {port_to_monitor}"
PICKLE_FILE = "/data/" + (os.getenv("PICKLE_FILE") or "timers.pkl")

# Program data
ip_timers = {}  # This will store the timers for each triggering IP

# Program data
ip_timers = {}  # This will store the timers for each triggering IP


def load_timers():
    """
    Load timer data from a pickle file.

    This function attempts to load pickled data from a specified pickle file.
    If the file exists and can be unpickled, it updates the `ip_timers` with the loaded data.
    If the file cannot be unpickled or does not exist, it calls `update_timers` to update 
    `ip_timers` with default or new data. After loading or updating, it logs the current state 
    of `ip_timers`.

    Returns:
        dict: The updated `ip_timers` dictionary containing the timer data.

    Side Effects:
        - Reads from a file specified by the global `PICKLE_FILE`.
        - Updates the global `ip_timers` dictionary.
        - Logs information and debug messages.
    """
    # Load pickled data from file
    if os.path.exists(PICKLE_FILE):
        try:
            with open(PICKLE_FILE, "rb") as file:
                ip_timers.update(pickle.load(file))
        except pickle.UnpicklingError as e:
            logger.debug(f"Error loading pickle file: {PICKLE_FILE} - {e}")
            update_timers()
    else:
        update_timers()
    logger.info(f"Loaded pickle file: {PICKLE_FILE} - ip_timers: {ip_timers}")
    return ip_timers


def update_timers():
    """
    Update and save the timer data to a pickle file.

    This function serializes the current state of the `ip_timers` dictionary and saves it
    to a pickle file specified by the global variable `PICKLE_FILE`. After saving the data, 
    it logs the updated state of `ip_timers`.

    Returns:
        dict: The `ip_timers` dictionary containing the updated timer data.

    Side Effects:
        - Writes to a file specified by the global `PICKLE_FILE`.
        - Serializes the global `ip_timers` dictionary.
        - Logs information messages.
    """
    with open(PICKLE_FILE, "wb") as file:
        pickle.dump(dict(ip_timers), file)
    logger.info(f"Updated pickle file: {PICKLE_FILE} - ip_timers: {ip_timers}")

    return ip_timers


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
    rule_check = (f"{base_cmd} -C PREROUTING -i {iface} -d {iface_ip} "
                  f"-p tcp --dport {port} -s {ip} -j ACCEPT")
    rule_add = (f"{base_cmd} -I PREROUTING -i {iface} -d {iface_ip} "
                f"-p tcp --dport {port} -s {ip} -j ACCEPT")

    # Open the port for the given IP if it's not already open
    if run_cmd(rule_check) == 0:
        logger.debug(f"Port: {port} already open for source IP address: {ip}")
    else:
        run_cmd(rule_add)
        logger.info(f"Port {port} opened for IP: {ip}")
    # Set the timer for this IP
    ip_timers[ip] = {port: time.time()}
    update_timers()


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
        dst_port = packet[TCP].dport
        open_port(src_ip, dst_port)


def ensure_drop_rules(port):
    """
    Ensures that a DROP rule exists in iptables for a specific port.

    This function checks if an iptables DROP rule exists for the specified port. 
    If it does not exist, the function adds the rule. It uses the `iptables` 
    command with the mangle table to manage the rules. It logs information about 
    whether the rule was added or already existed.

    Parameters:
    port (int): The port number for which the DROP rule should be checked or added.

    Side Effects:
        - Executes system commands to interact with iptables.
        - Logs information about the existence or addition of DROP rules.

    Returns:
    None
    """
    # Common parts of the command
    iptables_base_cmd = "/sbin/iptables -t mangle"
    iptables_common_args = f"-i {iface} -d {iface_ip} -p tcp --dport {port}"

    # Check if the DROP rule for port exists, and if not, add it
    check_cmd = (f"{iptables_base_cmd} -C PREROUTING "
                 f"{iptables_common_args} -j DROP")
    add_cmd = (f"{iptables_base_cmd} -I PREROUTING "
               f"{iptables_common_args} -j DROP")

    if run_cmd(check_cmd) != 0:
        run_cmd(add_cmd)
        logger.info(f"DROP rule added for port {port}")
    else:
        logger.info(f"DROP rule already existing for port {port}")


def run_cmd(cmd):
    """
    Executes a system command passed as a string.

    This function takes a command string, splits it into a list of arguments, 
    and then executes it using `subprocess.run`. It captures both the standard 
    output and standard error. The function is designed to handle exceptions that 
    may occur if the command execution fails, logging the event and setting an 
    appropriate exit code.

    Parameters:
    cmd (str): The system command to be executed.

    Returns:
    int: The exit code of the command execution. Returns 0 if the command executes 
    successfully, and 1 if there is a `CalledProcessError` exception (indicating 
    that the command failed).

    Side Effects:
        - Executes a system command.
        - Logs debug information about the command execution and its outcome.
    """
    logger.debug(f"Running command: {cmd}")
    # exit_code = subprocess.run(cmd.split(' '), check=True)
    try:
        subprocess.run(
            cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        exit_code = 0  # Rule exists
    except subprocess.CalledProcessError:
        exit_code = 1  # Rule doesn't exist
    logger.debug(f"Exit code: {exit_code}")
    return exit_code


if __name__ == "__main__":
    # Ensure default behaviour
    ensure_drop_rules(port_to_monitor)
    for p in ports_to_open:
        ensure_drop_rules(p)
    # load old timers
    ip_timers = load_timers()
    # Capturing traffic
    sniff(filter=filter_expr, iface=iface, prn=process_packet, store=0)
