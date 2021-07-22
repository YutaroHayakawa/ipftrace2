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
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <fts.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "ipft.h"

static int
fill_sym2info(struct ipft_symsdb *sdb, struct btf *btf)
{
  int error;
  struct ipft_syminfo sinfo;
  const struct btf_param *params;
  const char *func_name, *st_name;
  const struct btf_type *t, *func_proto;

  for (uint32_t id = 0; (t = btf__type_by_id(btf, id)); id++) {
    if (!btf_is_func(t)) {
      continue;
    }

    func_name = btf__str_by_offset(btf, t->name_off);
    func_proto = btf__type_by_id(btf, t->type);
    params = btf_params(func_proto);

    for (uint16_t i = 0; i < btf_vlen(func_proto) && i < MAX_SKB_POS - 1; i++) {
      t = btf__type_by_id(btf, params[i].type);
      if (!btf_is_ptr(t)) {
        continue;
      }

      t = btf__type_by_id(btf, t->type);
      if (!btf_is_struct(t)) {
        continue;
      }

      st_name = btf__str_by_offset(btf, t->name_off);
      if (strcmp(st_name, "sk_buff") != 0) {
        continue;
      }

      sinfo.skb_pos = i + 1;

      error = symsdb_put_sym2info(sdb, func_name, &sinfo);
      if (error != -2 && error != 0) {
        fprintf(stderr, "symsdb_put_sym2info failed\n");
        return -1;
      }

      break;
    }
  }

  return 0;
}

int
kernel_btf_fill_sym2info(struct ipft_symsdb *sdb)
{
  FTS *fts;
  FTSENT *f;
  int error;
  struct btf *btf, *vmlinux_btf;
  char *const path_argv[] = {"/sys/kernel/btf", NULL};

  vmlinux_btf = libbpf_find_kernel_btf();
  if (vmlinux_btf == NULL) {
    fprintf(stderr, "libbpf_find_kernel_btf failed\n");
    return -1;
  }

  error = fill_sym2info(sdb, vmlinux_btf);
  if (error == -1) {
    fprintf(stderr, "fill_sym2info failed\n");
    return -1;
  }

  /*
   * If kernel doesn't support sysfs BTF, skip loading
   * modules since currently we are not supporting it.
   */
  if (access("/sys/kernel/btf/vmlinux", R_OK) != 0) {
    return 0;
  }

  fts = fts_open(path_argv, FTS_NOSTAT | FTS_LOGICAL, NULL);
  if (fts == NULL) {
    fprintf(stderr, "fts_open failed: %s\n", strerror(errno));
    return -1;
  }

  while ((f = fts_read(fts)) != NULL) {
    switch (f->fts_info) {
    case FTS_F:
      if (strcmp(f->fts_name, "vmlinux") == 0) {
        continue;
      }

      btf = btf__parse_raw_split(f->fts_accpath, vmlinux_btf);
      if (btf == NULL) {
        fprintf(stderr, "btf__parse_raw failed\n");
        return -1;
      }

      error = fill_sym2info(sdb, btf);
      if (error == -1) {
        fprintf(stderr, "fill_sym2info failed\n");
        return -1;
      }

      break;
    }
  }

  fts_close(fts);

  return 0;
}
