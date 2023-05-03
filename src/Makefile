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
  script_lua.o \
  script_bpf.o \

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

%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $^

%.bpf.o.h: %.bpf.o
	echo "// clang-format off" > $@
	$(XXD) -i $^ >> $@
	echo "// clang-format on" >> $@

format:
	clang-format -i *.c
	clang-format -i *.h

clean:
	- rm -f $(OBJS) $(BPF_OBJS) $(BPF_HEADERS) ipft 
