CLANG ?= clang
XXD ?= xxd

OBJS := \
  ipft.o \
  output.o \
  output_aggregate.o \
  output_json.o \
  regex.o \
  symsdb.o \
  tracer.o \
  utils.o \
  script.o \

CFLAGS := \
  -g \
  -Wall \
  -Wextra \
  -I compat \
  -I compat/uapi \

LDFLAGS := \
  -static \

LDLIBS := \
  -lbpf \
  -lz \
  -lelf \
  -lpcre2-8 \
  -llua \
  -lpthread \
  -ldl \
  -lm \
  -lfts \

ARCH := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := \
  -g \
  -O3 \
  -I compat \
  -target bpf \
  -D__TARGET_ARCH_$(ARCH)

BPF_OBJS := \
  ipft_kprobe.bpf.o \
  ipft_ftrace.bpf.o \
  ipft_kprobe_multi.bpf.o \
  null_module.bpf.o \

BPF_HEADERS := \
  ipft_kprobe.bpf.o.h \
  ipft_ftrace.bpf.o.h \
  ipft_kprobe_multi.bpf.o.h \
  null_module.bpf.o.h \

ipft: $(OBJS)

tracer.o: $(BPF_HEADERS)

ipft_kprobe.bpf.o: ipft_kprobe.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $^

ipft_kprobe.bpf.o.h: ipft_kprobe.bpf.o
	xxd -i ipft_kprobe.bpf.o > ipft_kprobe.bpf.o.h

ipft_ftrace.bpf.o: ipft_ftrace.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $^

ipft_ftrace.bpf.o.h: ipft_ftrace.bpf.o
	xxd -i ipft_ftrace.bpf.o > ipft_ftrace.bpf.o.h

ipft_kprobe_multi.bpf.o: ipft_kprobe_multi.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $^

ipft_kprobe_multi.bpf.o.h: ipft_kprobe_multi.bpf.o
	xxd -i ipft_kprobe_multi.bpf.o > ipft_kprobe_multi.bpf.o.h

null_module.bpf.o: null_module.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $^

null_module.bpf.o.h: null_module.bpf.o 
	xxd -i null_module.bpf.o > null_module.bpf.o.h

format:
	clang-format -i *.c
	clang-format -i *.h

clean:
	- rm -f $(OBJS) $(BPF_OBJS) $(BPF_HEADERS) ipft 
