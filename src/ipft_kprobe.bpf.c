#include <linux/ptrace.h>

#include "ipft_common.bpf.h"

SEC("kprobe/ipft_main1") void ipft_main1(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main2") void ipft_main2(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main3") void ipft_main3(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main4") void ipft_main4(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
  ipft_body(ctx, skb);
}

SEC("kprobe/ipft_main5") void ipft_main5(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM5(ctx);
  ipft_body(ctx, skb);
}
