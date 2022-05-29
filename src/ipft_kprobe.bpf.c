#include <linux/ptrace.h>

#include "ipft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
  return PT_REGS_IP((struct pt_regs *)ctx) - 1;
}

#define ipft_main(skb_pos, perm_pos) \
SEC("kprobe/ipft_main" #skb_pos) int ipft_main##skb_pos(struct pt_regs *ctx) \
{ \
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##perm_pos(ctx); \
  return ipft_body(ctx, skb, 0); \
}

ipft_main(0, 1)
ipft_main(1, 2)
ipft_main(2, 3)
ipft_main(3, 4)
ipft_main(4, 5)
