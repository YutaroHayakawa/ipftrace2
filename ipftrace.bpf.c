/*
 * Work around for "'asm goto' constructs are not supported yet" error
 * https://github.com/iovisor/bcc/issues/2119
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

#define BPF
#include "ipftrace.h"

static struct bpf_map_def ctrl_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(uint32_t),
  .value_size = sizeof(struct ipft_ctrl_data),
  .max_entries = 1
};

static struct bpf_map_def events = {
  .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
  .key_size = sizeof(uint32_t),
  .value_size = sizeof(uint32_t),
  .max_entries = 64
};

static __always_inline void
ipftrace_main(struct pt_regs *ctx, uint8_t *skb)
{
  int error;
  uint32_t idx = 0, mark;
  struct ipft_trace t;
  struct ipft_ctrl_data *cdata;

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
    bpf_perf_event_output(ctx, &events,
        BPF_F_CURRENT_CPU, &t, sizeof(t));
  }
}

#define ipftrace_mainx(x) \
SEC("kprobe/ipftrace_main" #x) void \
ipftrace_main##x(struct pt_regs *ctx) \
{ \
  uint8_t *skb = \
    (uint8_t *)PT_REGS_PARM##x(ctx); \
  return ipftrace_main(ctx, skb); \
}

ipftrace_mainx(1)
ipftrace_mainx(2)
ipftrace_mainx(3)
ipftrace_mainx(4)

SEC("license") char _license[] = "GPL";
