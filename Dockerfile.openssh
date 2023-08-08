FROM python:alpine3.16

ARG UID=0
ARG GID=0

USER root
WORKDIR /sniffer

RUN apk update \
    && apk add libpcap-dev \
    && apk add --no-cache --virtual .build-deps build-base libpcap-dev linux-headers iptables \
    && pip install scapy psutil \
    && rm -rf /var/cache/apk/*

COPY openssh.py .

CMD ["python3", "openssh.py"]
