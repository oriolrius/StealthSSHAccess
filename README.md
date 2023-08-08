# Description

A Python-based tool for sniffing UDP packets on a given network interface. The payload from the UDP packets is extracted and logged, and can optionally be forwarded to a specified IP address over UDP.

# Build the image

This tool is built on the official Python image and uses the lightweight Alpine Linux to minimize the final image size. The expected size is approximately 270MB.

```
docker-compose build
```

# Configuration

You can configure the sniffer by setting environment variables in the `docker-compose` file.

```
# default values:
LOGLEVEL=INFO
IFACE=qvs1
FILTER=(udp and port 50222)
UDP_IP=10.2.88.26
UDP_PORT=50222
```

# Run

```
docker-compose up -d
```

# Debugging

```
docker run -it --rm --network=host --privileged ymbihq/weatherstation_sniffer:latest /bin/sh
# then run the entry command in the /sniffer folder
python3 udp_sniffer.py
# or use any other commands you need for debugging.
```

# Resources:

- https://git.oriolrius.cat/oriolrius/udp_sniffer
