CLANG ?= clang
XXD ?= xxd
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CFLAGS := \
  -g \
  -O3 \
  -I compat \
  -target bpf \
  -D__TARGET_ARCH_$(ARCH)
  

.PHONY: all
all: ipft.bpf.o null_module.bpf.o

ipft.bpf.o: ipft.bpf.c
	$(CLANG) $(CFLAGS) -c $^
	xxd -i ipft.bpf.o > ipft.bpf.o.h

null_module.bpf.o: null_module.bpf.c
	$(CLANG) $(CFLAGS) -c $^
	xxd -i null_module.bpf.o > null_module.bpf.o.h
