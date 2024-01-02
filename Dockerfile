FROM alpine:3.19

ARG UID=0
ARG GID=0

USER root
WORKDIR /sniffer

# Install necessary packages and Python libraries
RUN apk update
RUN apk add --no-cache gcc python3 python3-dev py3-pip libpcap-dev build-base linux-headers openssh-client

RUN apk add --no-cache py3-psutil
RUN python3 -m venv venv \
    && source venv/bin/activate \
    && pip3 install --upgrade pip \
    && pip3 install scapy 
RUN apk del build-base gcc python3-dev linux-headers
RUN rm -rf /var/cache/apk/*

COPY *.py ./
