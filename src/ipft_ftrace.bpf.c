/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include "ipft_common.bpf.h"

SEC("fentry/ipft_main1") void ipft_main1(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[0];
  ipft_body(ctx, skb);
}

SEC("fentry/ipft_main2") void ipft_main2(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[1];
  ipft_body(ctx, skb);
}

SEC("fentry/ipft_main3") void ipft_main3(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[2];
  ipft_body(ctx, skb);
}

SEC("fentry/ipft_main4") void ipft_main4(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[3];
  ipft_body(ctx, skb);
}

SEC("fentry/ipft_main5") void ipft_main5(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[4];
  ipft_body(ctx, skb);
}

char LICENSE[] SEC("license") = "GPL";
