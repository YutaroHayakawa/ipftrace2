CLANG?=clang

CC=$(CLANG)
CFLAGS=-target bpf -O3 -c -g

OBJS= \
	gso.bpf.o

all: $(OBJS)

%.o: %.c
	$(CLANG) $(CFLAGS) $<
