import os
import logging
import psutil
import time
import time
from openssh import update_timers, load_timers, run_cmd

# Debug
LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(level=LOGLEVEL, format=FORMAT, handlers=[logging.StreamHandler()])
logger = logging.getLogger("closessh")
logger.debug(f"LOGLEVEL = {LOGLEVEL}")

# Configuration
TIMEOUT = int(os.getenv("TIMEOUT")) if os.getenv("TIMEOUT") is not None else 600
WAIT_LOOP = int(os.getenv("WAIT_LOOP")) if os.getenv("WAIT_LOOP") is not None else 60

iface = os.getenv("IFACE") or "eth0"
iface_ip = os.getenv("IFACE_IP") or "172.19.0.2"
port_to_monitor = [
    int(port) for port in (os.getenv("PORT_TO_MONITOR") or "55888").split(",")
]
port_to_open = [int(port) for port in (os.getenv("PORT_TO_OPEN") or "55222").split(",")]
filter_expr = f"tcp port {' or tcp port '.join(str(port) for port in port_to_monitor)}"

PICKLE_FILE = "/data/" + (os.getenv("PICKLE_FILE") or "timers.pkl")

# Program data
ip_timers = {}


def check_and_close_ports(ip):
    for port in port_to_open:
        # Check if there is an active connection from this IP
        for connection in psutil.net_connections(kind="inet"):
            # logger.debug(f'connection: {connection}')
            comparison_results = (
                connection.laddr.port == port,
                connection.status == "ESTABLISHED",
                connection.raddr
                and connection.raddr[0]
                == ip,  # check if raddr is not empty and access the IP address from the tuple
            )
            if all(comparison_results):
                logger.info(
                    f"SSH connection detected from triggering IP {ip}, resetting timer to check again later"
                )
                ip_timers[ip] = time.time()

        # Check if it's unsed for more than TIMEOUT
        ttl = time.time() - ip_timers[ip]
        logger.debug(
            f"Calculating Time-to-live (TTL) for IP {ip}. TTL: {ttl}, TIMEOUT: {TIMEOUT}."
        )
        if ttl > TIMEOUT:
            close_port(ip, port)


def close_port(ip, port):
    # If no active connections are found, remove the ACCEPT entry for this IP
    run_cmd(
        f"/sbin/iptables -t mangle -D PREROUTING -i {iface} -d {iface_ip} -p tcp --dport {port} -s {ip} -j ACCEPT"
    )

    logger.info(f"Removed ACCEPT rule for IP: {ip}")
    try:
        del ip_timers[ip]
        update_timers()
    except KeyError:
        pass


if __name__ == "__main__":
    while True:
        ip_timers = load_timers()
        logger.info(ip_timers)
        for ip in dict(
            ip_timers
        ):  # make a copy for iterating, avoid problems removing items of the dict
            logger.debug(f"check_and_close_ports: {ip}")
            check_and_close_ports(ip)
        time.sleep(WAIT_LOOP)  # Sleep for a short time to prevent busy-waiting
