/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020-present Yutaro Hayakawa
 */

#include <stdint.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct gso_info {
  unsigned int len;
  uint16_t gso_size;
  uint16_t gso_segs;
  uint32_t gso_type;
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
  uint16_t gso_size;
  uint16_t gso_segs;
  uint32_t gso_type;
};

/*
 * Don't forget to annotate your program with __hidden attribute.
 * This is important especially you are using the kernel version
 * less than 5.12. This avoids too strict kernel verification and
 * overcome some feature limitation. Please see below for more
 * detail.
 *
 * Avoid strict verification against global functions by __hidden
 * https://github.com/libbpf/libbpf/commit/3319982d34ddc51a2807ccc92445d9a9d9089dcf
 *
 * There was no support of pointer argument for global functions with <= 5.12
 * https://github.com/torvalds/linux/commit/e5069b9c23b3857db986c58801bebe450cff3392
 */
__hidden int
module(struct pt_regs *ctx, struct sk_buff *skb, uint8_t data[64])
{
  unsigned int end;
  unsigned char *head;
  struct skb_shared_info *shinfo;
  struct gso_info *info = (struct gso_info *)data;

  head = BPF_CORE_READ(skb, head);
  end = BPF_CORE_READ(skb, end);

  /*
   * This calcuration only works when the kernel is compiled
   * with NET_SKBUFF_DATA_USES_OFFSET=y because if it set to
   * 'n', type of end is unsigned char *.
   */
  shinfo = (struct skb_shared_info *)(head + end);

  info->len = BPF_CORE_READ(skb, len);
  info->gso_size = BPF_CORE_READ(shinfo, gso_size);
  info->gso_segs = BPF_CORE_READ(shinfo, gso_segs);
  info->gso_type = BPF_CORE_READ(shinfo, gso_type);

  return 0;
}
