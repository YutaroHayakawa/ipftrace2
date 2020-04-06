/*
 * Work around for "'asm goto' constructs are not supported yet" error
 * https://github.com/iovisor/bcc/issues/2119
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF
#include "ipftrace.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, struct ipft_ctrl_data);
} ctrl_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline void ipftrace_main(struct pt_regs *ctx, uint8_t *skb) {
  struct ipft_trace t = {};
  struct ipft_ctrl_data *cdata;
  uint32_t idx = 0, mark;

  cdata = bpf_map_lookup_elem(&ctrl_map, &idx);
  if (cdata == NULL) {
    return;
  }

  if (cdata->mark == 0) {
    return;
  }

  bpf_probe_read(&mark, sizeof(mark), skb + cdata->mark_offset);

  if (mark == cdata->mark) {
    t.tstamp = bpf_ktime_get_ns();
    t.faddr = PT_REGS_IP(ctx);
    t.skb_addr = (uint64_t)skb;
    t.processor_id = bpf_get_smp_processor_id();

    /*
     * This function actually does nothing
     * instead, it will be replaced to the
     * module code
     */
    ipft_module_callsite(t.data, skb);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &t, sizeof(t));
  }
}

#define ipftrace_mainx(x)                                                      \
  SEC("kprobe/ipftrace_main" #x) void ipftrace_main##x(struct pt_regs *ctx) {  \
    uint8_t *skb = (uint8_t *)PT_REGS_PARM##x(ctx);                            \
    return ipftrace_main(ctx, skb);                                            \
  }

ipftrace_mainx(1) ipftrace_mainx(2) ipftrace_mainx(3) ipftrace_mainx(4)

    SEC("license") char _license[] = "GPL";
