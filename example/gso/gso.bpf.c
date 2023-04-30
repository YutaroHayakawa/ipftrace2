/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020-present Yutaro Hayakawa
 */

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event {
  unsigned int len;
  __u16 gso_size;
  __u16 gso_segs;
  __u32 gso_type;
};

/*
 * These are the only subset of actual sk_buff or skb_shared_info
 * definitions but no problem. Because BPF-CORE feature of libbpf
 * loader takes care of rewrite this program based on actual
 * definition from kernel BTF
 */
struct sk_buff {
  unsigned int len;
  unsigned char *head;
  unsigned int end;
};

struct skb_shared_info {
  __u16 gso_size;
  __u16 gso_segs;
  __u32 gso_type;
};

__hidden int
module(void *ctx, struct sk_buff *skb, __u8 data[64])
{
  unsigned int end;
  unsigned char *head;
  struct skb_shared_info *shinfo;
  struct event *ev = (struct event *)data;

  head = BPF_CORE_READ(skb, head);
  end = BPF_CORE_READ(skb, end);

  /*
   * This calcuration only works when the kernel is compiled
   * with NET_SKBUFF_DATA_USES_OFFSET=y because if it set to
   * 'n', type of end is unsigned char *.
   */
  shinfo = (struct skb_shared_info *)(head + end);

  ev->len = BPF_CORE_READ(skb, len);
  ev->gso_size = BPF_CORE_READ(shinfo, gso_size);
  ev->gso_segs = BPF_CORE_READ(shinfo, gso_segs);
  ev->gso_type = BPF_CORE_READ(shinfo, gso_type);

  return 0;
}
