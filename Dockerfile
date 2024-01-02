FROM ubuntu:14.04

ARG UID=0
ARG GID=0
ARG IPTABLES_PKG

USER root
WORKDIR /sniffer

# Install necessary packages and Python libraries
RUN apt-get update && apt-get install -y \
    gcc \
    python3 \
    python3-dev \
    python3-pip \
    libpcap-dev \
    build-essential \
    linux-headers-$(uname -r)

# Install iptables or iptables-legacy based on the build argument
# Note: Ubuntu 14.04 may not have a separate iptables-legacy package
RUN if [ "${IPTABLES_PKG}" = "legacy" ]; then \
      apt-get install -y iptables; \
    else \
      apt-get install -y iptables; \
    fi

# Install psutil
RUN pip3 install psutil

# Install scapy
RUN pip3 install scapy

# Cleanup to reduce image size
RUN apt-get remove --purge -y gcc python3-dev build-essential linux-headers-$(uname -r) \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY *.py ./
