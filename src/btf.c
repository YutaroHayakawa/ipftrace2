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

struct btf_debuginfo {
  struct ipft_debuginfo base;
  struct btf *btf;
  struct btf_type **types;
  size_t ntypes;
};

static struct btf_header *
get_btf_hdr(struct btf *btf)
{
  __unused uint32_t size;
  return (struct btf_header *)btf__get_raw_data(btf, &size);
}

static ssize_t
btf_type_size(struct btf_type *t)
{
  ssize_t base = sizeof(*t);
  uint16_t vlen = BTF_INFO_VLEN(t->info);

  switch (BTF_INFO_KIND(t->info)) {
  case BTF_KIND_FWD:
  case BTF_KIND_CONST:
  case BTF_KIND_VOLATILE:
  case BTF_KIND_RESTRICT:
  case BTF_KIND_PTR:
  case BTF_KIND_TYPEDEF:
  case BTF_KIND_FUNC:
    return base;
  case BTF_KIND_INT:
    return base + sizeof(uint32_t);
  case BTF_KIND_ENUM:
    return base + vlen * sizeof(struct btf_enum);
  case BTF_KIND_ARRAY:
    return base + sizeof(struct btf_array);
  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION:
    return base + vlen * sizeof(struct btf_member);
  case BTF_KIND_FUNC_PROTO:
    return base + vlen * sizeof(struct btf_param);
  case BTF_KIND_VAR:
    return base + sizeof(struct btf_var);
  case BTF_KIND_DATASEC:
    return base + vlen * sizeof(struct btf_var_secinfo);
  default:
    fprintf(stderr, "Unsupported BTF_KIND:%u\n", BTF_INFO_KIND(t->info));
    return -1;
  }
}

static int
parse_types(struct btf_debuginfo *dinfo)
{
  ssize_t tsize;
  uint8_t *cur, *end;
  size_t idx, ntypes;
  struct btf_header *hdr;
  struct btf_type *type, **types;

  hdr = get_btf_hdr(dinfo->btf);

  ntypes = hdr->type_len / sizeof(**types) + 2;

  types = calloc(sizeof(*types), ntypes);
  if (types == NULL) {
    perror("calloc");
    return -1;
  }

  idx = 1;
  cur = (uint8_t *)(hdr + 1) + hdr->type_off;
  end = (uint8_t *)(hdr + 1) + hdr->str_off;
  while (cur < end) {
    type = (struct btf_type *)cur;
    tsize = btf_type_size(type);
    if (tsize == -1) {
      fprintf(stderr, "Failed to get type size\n");
      return -1;
    }
    cur += tsize;
    types[idx] = type;
    idx++;
  }

  dinfo->types = types;
  dinfo->ntypes = idx;

  return 0;
}

static int
fill_sym2info(struct btf_debuginfo *dinfo, struct ipft_symsdb *sdb)
{
  int error;
  struct btf_header *hdr;
  struct ipft_syminfo sinfo;
  char *str_sec, *st_name, *func_name;
  struct btf_param *param_base, *param;
  struct btf_type **types, *ptr, *st, *func, *func_proto;

  hdr = get_btf_hdr(dinfo->btf);
  str_sec = (char *)(hdr + 1) + hdr->str_off;

  types = dinfo->types;

  for (size_t i = 1; i < dinfo->ntypes; i++) {
    func = types[i];
    if (BTF_INFO_KIND(func->info) == BTF_KIND_FUNC) {
      func_name = str_sec + func->name_off;
      func_proto = types[func->type];
      param_base = (struct btf_param *)(func_proto + 1);
      for (uint16_t i = 0;
           i < BTF_INFO_VLEN(func_proto->info) && i < MAX_SKB_POS - 1; i++) {
        param = param_base + i;

        /*
         * Variable length argument
         */
        if (param->type == 0) {
          break;
        }

        ptr = types[param->type];
        if (BTF_INFO_KIND(ptr->info) == BTF_KIND_PTR) {
          st = types[ptr->type];
          /* ptr->type == 0 means void * */
          if (ptr->type != 0 && BTF_INFO_KIND(st->info) == BTF_KIND_STRUCT) {
            st_name = str_sec + st->name_off;
            if (strcmp(st_name, "sk_buff") == 0) {
              sinfo.skb_pos = i + 1;

              error = symsdb_put_sym2info(sdb, func_name, &sinfo);
              if (error == -1) {
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

static int
btf_debuginfo_fill_sym2info(struct ipft_debuginfo *_dinfo,
                            struct ipft_symsdb *sdb)
{
  return fill_sym2info((struct btf_debuginfo *)_dinfo, sdb);
}

int
btf_debuginfo_create(struct ipft_debuginfo **dinfop)
{
  int error = 0;
  struct btf_debuginfo *dinfo;

  dinfo = malloc(sizeof(*dinfo));
  if (dinfo == NULL) {
    perror("malloc");
    return -1;
  }

  dinfo->btf = libbpf_find_kernel_btf();
  if (dinfo->btf == NULL) {
    fprintf(stderr, "libbpf_find_kernel_btf failed\n");
    return -1;
  }

  error = parse_types(dinfo);
  if (error == -1) {
    fprintf(stderr, "parse_types\n");
    return -1;
  }

  dinfo->base.fill_sym2info = btf_debuginfo_fill_sym2info;

  *dinfop = (struct ipft_debuginfo *)dinfo;

  return 0;
}
