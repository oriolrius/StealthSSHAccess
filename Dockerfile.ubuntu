FROM ubuntu:latest

ARG UID=0
ARG GID=0

USER root
WORKDIR /sniffer

# Install necessary packages and Python libraries
RUN apt-get update \
    && apt-get install -y python3 python3-pip libpcap-dev iptables build-essential \
    && pip3 install scapy psutil \
    # Clean up to reduce image size
    && apt-get remove --purge -y build-essential \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY *.py .
