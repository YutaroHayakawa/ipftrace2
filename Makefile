LIBBPF_DIR=deps/libbpf-0.0.7
LIBBPF_INCLUDE=$(LIBBPF_DIR)/src
LIBBPF_LIB=$(LIBBPF_DIR)/src/libbpf.a

CFLAGS := -g -Ofast -Wall -std=gnu99 -I $(LIBBPF_INCLUDE)
LDLIBS := -lelf -ldw -lz -lpthread

OBJS := symsdb.o trace_store.o ipftrace.o

all: ipftrace2 $(LIBBPF_LIB)

clean:
	rm -f ipftrace2
	rm -f $(OBJS)

ipftrace2: $(OBJS) $(LIBBPF_LIB)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBBPF_LIB) $(LDLIBS)

$(LIBBPF_LIB): $(LIBBPF_DIR)
	make -C $(LIBBPF_DIR)/src

$(LIBBPF_DIR):
	tar xvf $@.tar.gz

.PHONY: clean
