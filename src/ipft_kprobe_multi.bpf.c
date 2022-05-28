#include <linux/ptrace.h>

#include "ipft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
  /*
   * kprobe.multi program relies on the ftrace, now we cannot
   * get function address from struct pt_regs.
   */
  return bpf_get_func_ip(ctx);
}

SEC("kprobe.multi/ipft_main0") int ipft_main0(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe.multi/ipft_main1") int ipft_main1(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe.multi/ipft_main2") int ipft_main2(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe.multi/ipft_main3") int ipft_main3(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);
  return ipft_body(ctx, skb, 0);
}

SEC("kprobe.multi/ipft_main4") int ipft_main4(struct pt_regs *ctx)
{
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM5(ctx);
  return ipft_body(ctx, skb, 0);
}
