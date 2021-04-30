#!/bin/bash

# Run this in project top

docker build -t ipftrace:latest -f docker/Dockerfile.build_static .
docker run --name ipft --rm -d --entrypoint /sbin/init ipftrace:latest
docker cp ipft:/ipftrace2/src/ipft .
docker cp ipft:/ipftrace2/src/ipft.bpf.o src/ipft.bpf.o
docker cp ipft:/ipftrace2/src/ipft.bpf.o.h src/ipft.bpf.o.h
docker cp ipft:/ipftrace2/src/null_module.bpf.o src/null_module.bpf.o
docker cp ipft:/ipftrace2/src/null_module.bpf.o.h src/null_module.bpf.o.h
docker stop ipft
