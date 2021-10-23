#!/bin/bash

# Run this in project top

docker build -t ipftrace:latest .
docker run --name ipft --rm -d --entrypoint /sbin/init ipftrace:latest
docker cp ipft:/ipftrace2/src/ipft .
docker cp ipft:/ipftrace2/src/ipft_kprobe.bpf.o src/ipft_kprobe.bpf.o
docker cp ipft:/ipftrace2/src/ipft_kprobe.bpf.o.h src/ipft_kprobe.bpf.o.h
docker cp ipft:/ipftrace2/src/null_module.bpf.o src/null_module.bpf.o
docker cp ipft:/ipftrace2/src/null_module.bpf.o.h src/null_module.bpf.o.h
docker stop ipft
