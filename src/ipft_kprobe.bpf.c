#include <linux/ptrace.h>

#include "ipft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
  return PT_REGS_IP((struct pt_regs *)ctx) - 1;
}

SEC("kprobe/ipft_main0") int ipft_main0(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe/ipft_main1") int ipft_main1(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe/ipft_main2") int ipft_main2(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe/ipft_main3") int ipft_main3(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe/ipft_main4") int ipft_main4(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM5(ctx);
  return ipft_body(ctx, skb, 0);
}
