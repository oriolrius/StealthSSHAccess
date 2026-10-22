FROM alpine:3.19

ARG UID=0
ARG GID=0
ARG IPTABLES_PKG

USER root
WORKDIR /sniffer

# Install necessary packages and Python libraries
RUN apk update
RUN apk add --no-cache gcc python3 python3-dev py3-pip libpcap-dev build-base linux-headers

# if IPTABLES_PKG is iptables-legacy then link /sbin/iptables to /sbin/iptables-legacy
RUN if [ "${IPTABLES_PKG}" = "legacy" ]; then \
      apk add --no-cache iptables-legacy; \
      ln -s /sbin/iptables-legacy /sbin/iptables; \
    else \
      apk add --no-cache iptables; \
    fi

RUN apk add --no-cache py3-psutil
RUN python3 -m venv venv \
    && source venv/bin/activate \
    && pip3 install --upgrade pip \
    && pip3 install scapy 
RUN apk del build-base gcc python3-dev linux-headers
RUN rm -rf /var/cache/apk/*

# eMudhra CA compromise (2026-10): distrust the affected roots — this EOL base gets
# no patched ca-certificates package.
RUN sed -i -e "s|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|" -e "s|^mozilla/Comodo_AAA_Services_root.crt|!&|" /etc/ca-certificates.conf \
 && update-ca-certificates --fresh >/dev/null

COPY *.py ./
