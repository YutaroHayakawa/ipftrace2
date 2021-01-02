/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/btf.h>

#include <bpf/btf.h>

#include "ipftrace.h"

int
kernel_btf_fill_sym2info(struct ipft_symsdb *sdb)
{
  int error;
  struct btf *btf;
  struct ipft_syminfo sinfo;
  const struct btf_param *params;
  const char *func_name, *st_name;
  const struct btf_type *t, *func_proto;

  btf = libbpf_find_kernel_btf();
  if (btf == NULL) {
    fprintf(stderr, "libbpf_find_kernel_btf failed\n");
    return -1;
  }

  for (uint32_t id = 0; (t = btf__type_by_id(btf, id)); id++) {
    if (btf_is_func(t)) {
      func_name = btf__str_by_offset(btf, t->name_off);
      func_proto = btf__type_by_id(btf, t->type);
      params = btf_params(func_proto);
      for (uint16_t i = 0;
          i < btf_vlen(func_proto) && i < MAX_SKB_POS - 1; i++) {
        t = btf__type_by_id(btf, params[i].type);
        if (btf_is_ptr(t)) {
          t = btf__type_by_id(btf, t->type);
          if (btf_is_struct(t)) {
            st_name = btf__str_by_offset(btf, t->name_off);
            if (strcmp(st_name, "sk_buff") == 0) {
              sinfo.skb_pos = i + 1;
              error = symsdb_put_sym2info(sdb, func_name, &sinfo);
              if (error != 0) {
                fprintf(stderr, "symsdb_put_sym2info failed\n");
                return -1;
              }
              break;
            }
          }
        }
      }
    }
  }

  return 0;
}
