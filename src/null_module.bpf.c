/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */

/*
 * Workaround to deal with missing weak symbol support. We can put
 * this function into ipft.bpf.c with weak symbol once it is supported.
 */
#include <stdint.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct sk_buff {
};

__hidden int
module(struct pt_regs *ctx, struct sk_buff *skb, uint8_t data[64])
{
  /* Do nothing */
  return 0;
}
