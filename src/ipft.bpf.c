#include <stdint.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ipftrace.h"

struct sk_buff {
  uint32_t mark;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint32_t));
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, struct ipft_trace_config);
} config SEC(".maps");

static __inline void
ipft_body(struct pt_regs *ctx, struct sk_buff *skb)
{
  int error;
  uint32_t mark;
  uint32_t idx = 0;
  struct ipft_trace trace = {0};
  struct ipft_trace_config *conf;

  conf = bpf_map_lookup_elem(&config, &idx);
  if (conf == NULL) {
    return;
  }

  mark = BPF_CORE_READ(skb, mark);
  if (mark == 0 || mark != target_mark) {
    return;
  }

  trace.skb_addr = (uint64_t)skb;
  trace.tstamp = bpf_ktime_get_ns();
  trace.faddr = PT_REGS_IP(ctx);
  trace.processor_id = bpf_get_smp_processor_id();

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
      &trace, sizeof(trace));
}

SEC("kprobe/ipft_main1") void
BPF_KPROBE(ipft_main1, struct sk_buff *skb)
{
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main2") void
BPF_KPROBE(ipft_main2, uint64_t arg1, struct sk_buff *skb) {
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main3") void
BPF_KPROBE(ipft_main3, uint64_t arg1, uint64_t arg2, struct sk_buff *skb) {
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main4") void
BPF_KPROBE(ipft_main4, uint64_t arg1, uint64_t arg2, uint64_t arg3, struct sk_buff *skb) {
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main5") void
BPF_KPROBE(ipft_main5, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, struct sk_buff *skb) {
  ipft_body(ctx, skb);
}

char LICENSE[] SEC("license") = "GPL";
