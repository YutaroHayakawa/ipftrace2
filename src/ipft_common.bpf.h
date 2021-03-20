/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/ptrace.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ipft.h"

#define __noinline __attribute__((noinline))

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

static __noinline int
module(void *ctx, struct sk_buff *skb, uint8_t data[64])
{
  data[0] = (uint8_t)ctx;
  data[1] = (uint8_t)skb;
  return (int)data;
}

static __inline void
ipft_body(void *ctx, struct sk_buff *skb)
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
  if ((mark & conf->mask) != (conf->mark & conf->mask)) {
    return;
  }

  trace.skb_addr = (uint64_t)skb;

  error = module(ctx, skb, trace.data);
  if (error != 0) {
    return;
  }

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &trace, sizeof(trace));
}
