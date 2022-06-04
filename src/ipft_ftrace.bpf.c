#include "ipft_body.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
  return bpf_get_func_ip(ctx);
}

#define ipft_main(skb_pos)                                                     \
  SEC("fentry/ipft_main" #skb_pos) int ipft_main##skb_pos(void **ctx)          \
  {                                                                            \
    struct sk_buff *skb = (struct sk_buff *)ctx[skb_pos];                      \
    return ipft_body(ctx, skb, 0);                                             \
  }                                                                            \
  SEC("fexit/ipft_main_return" #skb_pos)                                       \
  int ipft_main_return##skb_pos(void **ctx)                                    \
  {                                                                            \
    struct sk_buff *skb = (struct sk_buff *)ctx[skb_pos];                      \
    return ipft_body(ctx, skb, 1);                                             \
  }

ipft_main(0) ipft_main(1) ipft_main(2) ipft_main(3) ipft_main(4) ipft_main(5)
    ipft_main(6) ipft_main(7) ipft_main(8) ipft_main(9) ipft_main(10)
        ipft_main(11)
