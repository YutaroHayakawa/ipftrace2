/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2023-present Yutaro Hayakawa
 */

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __ipft_sec_skip __attribute__((section("__ipft_skip")))
#define __ipft_ref(name) name __ipft_sec_skip
#define __ipft_event_struct __ipft_event_struct __ipft_sec_skip
#define __ipft_fmt_hex __attribute__((btf_decl_tag("ipft:fmt:hex")))
#define __ipft_fmt_enum(ref) __attribute__((btf_decl_tag("ipft:fmt:enum:" #ref)))
#define __ipft_fmt_enum_flags(ref) __attribute__((btf_decl_tag("ipft:fmt:enum_flags:" #ref)))

enum {
  tcpv4           = 1 << 0,
  dodgy           = 1 << 1,
  tcp_ecn         = 1 << 2,
  tcp_fixedid     = 1 << 3,
  tcpv6           = 1 << 4,
  fcoe            = 1 << 5,
  gre             = 1 << 6,
  gre_csum        = 1 << 7,
  ipxip4          = 1 << 8,
  ipxip6          = 1 << 9,
  udp_tunnel      = 1 << 10,
  udp_tunnel_csum = 1 << 11,
  partial         = 1 << 12,
  tunnel_remcsum  = 1 << 13,
  sctp            = 1 << 14,
  esp             = 1 << 15,
  udp             = 1 << 16,
  udp_l4          = 1 << 17,
  flaglist        = 1 << 18,
} __ipft_ref(gso_types);

struct event {
  unsigned int len;
  __u16 gso_size;
  __u16 gso_segs;
  __u32 gso_type __ipft_fmt_enum_flags(gso_types);
} __ipft_event_struct;

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
