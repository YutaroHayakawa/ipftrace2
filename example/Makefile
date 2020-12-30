CLANG?=clang
LLVM_OBJCOPY=llvm-objcopy

CC=$(CLANG)
CFLAGS=-target bpf -O3 -c -g

OBJS= \
	gso.bpf.o

all: $(OBJS)

%.o: %.c
	$(CLANG) $(CFLAGS) $<
	$(LLVM_OBJCOPY) --remove-section=".eh_frame" --remove-section=".rel.eh_frame" $@

clean:
	- rm -f $(OBJS)
