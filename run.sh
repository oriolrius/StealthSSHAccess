#!/bin/bash

# Build Ubuntu-based image
docker build --build-arg BASE_IMAGE=ubuntu:latest -t yourname/image:ubuntu -f Dockerfile.ubuntu .

# Build Alpine-based image
docker build --build-arg BASE_IMAGE=alpine:latest -t yourname/image:alpine -f Dockerfile.alpine .
