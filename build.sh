#!/bin/bash

docker build --build-arg IPTABLES_PKG=legacy -t ymbihq/openssh -f Dockerfile .
