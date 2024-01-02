"""

"""
import os
import logging
import subprocess
import pickle

# Configuration
LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger("ssh_port_manager")

iface = os.getenv("IFACE", "eth0")
iface_ip = os.getenv("IFACE_IP", "172.19.0.2")
port_to_monitor = int(os.getenv("PORT_TO_MONITOR", "55888"))
ports_to_open = [int(port) for port in os.getenv("PORTS_TO_OPEN", "55222").split(",")]
TIMEOUT = int(os.getenv("TIMEOUT", "600"))
WAIT_LOOP = int(os.getenv("WAIT_LOOP", "60"))
PICKLE_FILE = "/data/" + os.getenv("PICKLE_FILE", "timers.pkl")

# Program data
ip_timers = {}

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
    except subprocess.CalledProcessError as e:
        exit_code = 1  # Rule doesn't exist
        logger.error(e)
    logger.debug(f"Exit code: {exit_code}")
    return exit_code
