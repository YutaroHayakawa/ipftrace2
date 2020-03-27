CFLAGS  += -g -O3 -Wall -Wextra -Werror -std=gnu99
LIBS    := -lelf -ldw -lz -lpthread

SRC     := symsdb.c tracedb.c ipftrace.c btf.c dwarf.c debuginfo.c kallsyms.c trace.c
BIN     := ipftrace2

ODIR    := obj
OBJ     := $(patsubst %.c,$(ODIR)/%.o,$(SRC))
LIBS    := $(LIBS)

CFLAGS  += -I$(ODIR)/include
LDFLAGS += -L$(ODIR)/lib64

LLC   ?= llc
CLANG ?= clang

KERNEL ?= /lib/modules/$(shell uname -r)/build/
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/i386/x86/')
LIBBPF := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/libbpf*.tar.gz)))

BPF_SRC    := ipftrace.bpf.c
BPF_OBJ    := ipftrace.bpf.o
BPF_OBJ_LL := ipftrace.bpf.ll
BPF_ELF_H  := ipftrace.elf.h

BPF_CFLAGS := \
	-g -O3 -Wall -std=gnu99 \
	-I$(ODIR)/include \
	-I$(KERNEL)/arch/$(ARCH)/include/generated/uapi \
	-I$(KERNEL)/arch/$(ARCH)/include/generated \
	-I$(KERNEL)/arch/$(ARCH)/include \
	-I$(KERNEL)/arch/$(ARCH)/include/uapi \
	-I$(KERNEL)/include \
	-I$(KERNEL)/include/uapi \
	-include $(KERNEL)/include/linux/kconfig.h \
	-I$(KERNEL)/include/generated/uapi \
	-S -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end \
	-Wno-tautological-compare -Wno-address-of-packed-member -Wno-unused-label \
	-emit-llvm

BPF_CFLAGS += -I$(KERNEL)/arch/$(ARCH)/include/generated/uapi
BPF_CFLAGS += -I$(KERNEL)/arch/$(ARCH)/include/generated
BPF_CFLAGS += -I$(KERNEL)/arch/$(ARCH)/include
BPF_CFLAGS += -I$(KERNEL)/arch/$(ARCH)/include/uapi
BPF_CFLAGS += -I$(KERNEL)/include
BPF_CFLAGS += -I$(KERNEL)/include/uapi
BPF_CFLAGS += -include $(KERNEL)/include/linux/kconfig.h
BPF_CFLAGS += -I$(KERNEL)/include/generated/uapi

DEPS       := $(ODIR)/lib64/libbpf.a

all: $(BIN)

clean:
	$(RM) -rf $(BIN) obj/* $(BPF_OBJ) $(BPF_OBJ_LL) $(BPF_ELF_H)

$(BIN): $(OBJ)
	@echo LINK $(BIN)
	@$(CC) $(LDFLAGS) -o $@ $^ $(DEPS) $(LIBS)

$(OBJ): $(BPF_ELF_H) | $(ODIR)

$(BPF_ELF_H): $(BPF_OBJ) | $(ODIR)
	echo "#pragma once" > $@
	xxd -i $(BPF_OBJ) >> $@

$(BPF_OBJ): $(BPF_OBJ_LL)
	$(LLC) -march=bpf -filetype=obj -o $@ $(BPF_OBJ_LL)

$(BPF_OBJ_LL): $(DEPS)
	$(CLANG) $(BPF_CFLAGS) -o $@ -c $(BPF_SRC)

$(ODIR):
	@mkdir -p $@

$(ODIR)/%.o : %.c
	@echo CC $<
	@$(CC) $(CFLAGS) -c -o $@ $<

$(ODIR)/$(LIBBPF): deps/$(LIBBPF).tar.gz | $(ODIR)
	@tar -C $(ODIR) -xf $<

$(ODIR)/lib64/libbpf.a: $(ODIR)/$(LIBBPF)
	@echo Building libbpf...
	@$(MAKE) -C $</src PREFIX=$(abspath $(ODIR)) install
	@$(MAKE) -C $</src PREFIX=$(abspath $(ODIR)) install_headers

.PHONY: all clean
