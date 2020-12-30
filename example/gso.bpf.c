#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct gso_info {
  uint16_t gso_size;
  uint16_t gso_segs;
  uint32_t gso_type;
};

extern int CONFIG_NET_SKBUFF_DATA_USES_OFFSET __kconfig;

int
module(void *ctx, struct sk_buff *skb, uint8_t data[64])
{
  uint8_t *head;
  struct skb_shared_info *shinfo;
  struct gso_info *info = (struct gso_info *)data;

  head = BPF_CORE_READ(skb, head);

  if (CONFIG_NET_SKBUFF_DATA_USES_OFFSET == TRI_YES) {
    unsigned int end = BPF_CORE_READ(skb, end);
    shinfo = (struct skb_shared_info *)(head + end);
  } else if (CONFIG_NET_SKBUFF_DATA_USES_OFFSET == TRI_NO) {
    uint8_t *end = BPF_CORE_READ(skb, end);
    shinfo = (struct skb_shared_info *)end;
  } else {
    // Unexpected case
    return -1;
  }

  info->gso_size = BPF_CORE_READ(shinfo, gso_size);
  info->gso_segs = BPF_CORE_READ(shinfo, gso_segs);
  info->gso_type = BPF_CORE_READ(shinfo, gso_type);

  return 0;
}
