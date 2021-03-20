CLANG?=clang
LLVM_OBJCOPY=llvm-objcopy
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

CFLAGS=\
	-c \
	-g \
	-O3 \
	-target bpf \
	-D__TARGET_ARCH_$(ARCH)

all:
	$(CLANG) $(CFLAGS) ipft_kprobe.bpf.c
	$(CLANG) $(CFLAGS) ipft_ftrace.bpf.c
	$(LLVM_OBJCOPY) --remove-section ".eh_frame" --remove-section ".rel.eh_frame" ipft_kprobe.bpf.o
	$(LLVM_OBJCOPY) --remove-section ".eh_frame" --remove-section ".rel.eh_frame" ipft_ftrace.bpf.o
	xxd -i ipft_kprobe.bpf.o > ipft_kprobe.bpf.o.h
	xxd -i ipft_ftrace.bpf.o > ipft_ftrace.bpf.o.h
