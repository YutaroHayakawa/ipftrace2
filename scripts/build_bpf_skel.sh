#!/bin/bash

# Run this in project top

ARCH=$(uname -m | sed 's/x86_64/x86/')

echo "Target arch: $ARCH"

cd src
clang -O3 -g -target bpf -D__TARGET_ARCH_${ARCH} -c ipft.bpf.c
# .eh_frame and .rel.eh_frame produces warning in libbpf. Remove it.
llvm-objcopy --remove-section=".eh_frame" --remove-section=".rel.eh_frame" ipft.bpf.o
bpftool gen skeleton ipft.bpf.o > ipft.bpf.skel.h
