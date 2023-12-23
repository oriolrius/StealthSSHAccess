# StealthSSHAccess

StealthSSHAccess is a smart and secure way to manage remote SSH access to your servers, and other ports. It keeps the SSH port shielded from unwanted attacks such as denial-of-service (DoS), brute force, and other malicious attempts. However, the need to have remote access remains essential, and StealthSSHAccess caters to this requirement in a stealthy and personalized way.

## How It Works

- **Monitoring for Intent**: The service continuously monitors a specific TCP port for any connection attempts.
- **Capturing the IP**: If an attempt is made on this monitored port, the IP address of the requester is captured. The initial connection attempt will fail, but this 'knock' on the port serves as a signal of intent to access.
- **Opening a Secure Door**: StealthSSHAccess then temporarily opens the SSH port, and/or a list of ports, exclusively for that captured IP address, allowing for a regular TCP connection.
- **Time-Bound Access**: The access is allowed for a pre-configured duration, defined by the `TIMEOUT` environment variable (default value in seconds). If the SSH, or any other port list in `PORTS_TO_OPEN`, access is use within the `TIMEOUT` duration, the ports are automatically closed for that specific IP, ensuring that the window of exposure is limited. This adds an additional layer of security by providing a narrow window of time for the authorized IP to connect to the SSH service, services at `PORTS_TO_OPEN`.
- **Closing Unused Port**: If the port remains unused during the allotted time, the access will be automatically revoked, and the port will be closed for that specific IP. This process is controlled by a continuous monitoring mechanism in the `closessh` service.
- **Persisting Access Information**: All the timers associated with IP addresses are persisted in a file defined by the `PICKLE_FILE` environment variable, ensuring that the system remains aware of pending access even across restarts. This allows the application to keep track of authorized IPs and the corresponding timeouts across service interruptions or restarts.

```
  Client             Monitored Port              SSH Port                  Server
    |                       |                         |                       |
    | --- Attempt on ---> [X] --- Capture IP ---> (✓) --- Open Port ---> SSH Access
        monitored port         (Connection fails)         (Specific IP only)
```

## Why StealthSSHAccess?

- **Enhanced Security**: By hiding the SSH port from unauthorized attempts, it greatly reduces the attack surface.
- **Selective Accessibility**: You control who gets access by simply attempting a connection to a specific port.
- **Dynamic Response**: It responds dynamically to legitimate access attempts, providing a smooth user experience.
- **Minimal Configuration**: With a simple configuration and deployment using Docker, StealthSSHAccess can be integrated into existing systems with ease.

StealthSSHAccess is a simple automation that helps you to add a new layer of security to your private remote access services. Ideal for administrators looking to maintain a high level of security while still enjoying the convenience of remote access.

## Services overview

- `openssh`: Monitors a specified TCP port, and when a SYN packet is detected on that port, opens another designated port for the source IP address.
- `closessh`: Checks for active connections to the opened port and closes it if there are no active connections for a specified timeout period.

## Requirements

- Docker
- Docker Compose

## Configuration

Configuration can be done via environment variables, which can be set in the `.env` file. A sample `.env` file is provided in `.env.sample`. Rename this file to `.env` and update the values as needed.

### Environment Variables

- `LOGLEVEL`: Logging level (e.g., DEBUG, INFO).
- `IFACE`: Network interface to monitor.
- `IFACE_IP`: IP address of the interface to monitor.
- `PORT_TO_MONITOR`: Port to monitor for SYN packets.
- `PORTS_TO_OPEN`: Coma separated list of ports to open for the source IP address.
- `PICKLE_FILE`: Path to the "pickle" file used to store timer information.
- `TIMEOUT`: Timeout in seconds for closing the opened port (only for closessh service).
- `WAIT_LOOP`: Time to wait between checks for active connections (only for closessh service).

## Build & Run

### Building the Images

From the project directory, run:

```bash
docker-compose build
```

### Running the Services

To run the services, execute:

```bash
docker-compose up -d
```

### Developing the code

To run the services, execute:

```bash
docker run --rm -it --env-file YOUR_PATH/.env.example -v YOUR_PATH/data:/data -v YOUR_PATH:/sniffer --privileged --network host ymbihq/openssh /bin/bash
```

## Data Persistence

The data related to the IP timers is persisted in the `./data` directory mapped in the volumes. Make sure this directory is writable by the Docker user.

## Note on Privileges

These services run with privileged access as they need to interact with the system's network configuration. Ensure that you understand the security implications before deploying them.

## Contributing

Please feel free to submit issues or pull requests as needed.

## License

StealthSSHAccess is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License. You are free to:

- Share — copy and redistribute the material in any medium or format
- Adapt — remix, transform, and build upon the material

Under the following terms:

- Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
- NonCommercial — You may not use the material for commercial purposes without prior consent from the author.

For the full license text, please visit [Creative Commons Attribution-NonCommercial 4.0 International License](https://creativecommons.org/licenses/by-nc/4.0/).
