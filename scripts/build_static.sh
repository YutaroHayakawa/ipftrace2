#!/bin/bash

# Run this in project top

docker build -t ipftrace:latest .
docker run --name ipft --rm -d --entrypoint /sbin/init ipftrace:latest
docker cp ipft:/ipftrace2/src/ipft .
docker stop ipft
