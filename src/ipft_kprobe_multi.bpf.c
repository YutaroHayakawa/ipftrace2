#include <linux/ptrace.h>

#include "ipft_common.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
  /*
   * kprobe.multi program relies on the ftrace, so we cannot
   * get function address from struct pt_regs.
   */
  return bpf_get_func_ip(ctx);
}

#define ipft_main(skb_pos, parm_pos)                                           \
  SEC("kprobe.multi/ipft_main" #skb_pos)                                       \
  int ipft_main##skb_pos(struct pt_regs *ctx)                                  \
  {                                                                            \
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM##parm_pos(ctx);       \
    return ipft_body(ctx, skb, 0);                                             \
  }

ipft_main(0, 1) ipft_main(1, 2) ipft_main(2, 3) ipft_main(3, 4) ipft_main(4, 5)
