#include "ipft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
  return bpf_get_func_ip(ctx);
}

SEC("fentry/ipft_main1") int ipft_main1(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[0];
  return ipft_body(ctx, skb, 0);
}

SEC("fentry/ipft_main2") int ipft_main2(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[1];
  return ipft_body(ctx, skb, 0);
}

SEC("fentry/ipft_main3") int ipft_main3(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[2];
  return ipft_body(ctx, skb, 0);
}

SEC("fentry/ipft_main4") int ipft_main4(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[3];
  return ipft_body(ctx, skb, 0);
}

SEC("fentry/ipft_main5") int ipft_main5(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[4];
  return ipft_body(ctx, skb, 0);
}

SEC("fexit/ipft_main_return1") int ipft_main_return1(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[0];
  return ipft_body(ctx, skb, 1);
}

SEC("fexit/ipft_main_return2") int ipft_main_return2(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[1];
  return ipft_body(ctx, skb, 1);
}

SEC("fexit/ipft_main_return3") int ipft_main_return3(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[2];
  return ipft_body(ctx, skb, 1);
}

SEC("fexit/ipft_main_return4") int ipft_main_return4(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[3];
  return ipft_body(ctx, skb, 1);
}

SEC("fexit/ipft_main_return5") int ipft_main_return5(void **ctx)
{
  struct sk_buff *skb = (struct sk_buff *)ctx[4];
  return ipft_body(ctx, skb, 1);
}