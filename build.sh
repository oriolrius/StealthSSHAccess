#!/bin/bash

docker build --network ymbihq_servers -t ymbihq/openssh:qnap -f Dockerfile .
