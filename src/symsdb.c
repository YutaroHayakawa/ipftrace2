/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <ctype.h>
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
#include "khash.h"

KHASH_MAP_INIT_STR(sym2info, struct ipft_syminfo *)
KHASH_MAP_INIT_INT64(addr2sym, char *)

struct ipft_symsdb {
  khash_t(sym2info) * sym2info;
  khash_t(addr2sym) * addr2sym;
};

size_t
symsdb_get_sym2info_total(struct ipft_symsdb *sdb)
{
  return kh_size(sdb->sym2info);
}

static int
symsdb_put_sym2info(struct ipft_symsdb *sdb, const char *name,
                    struct ipft_syminfo *sinfo)
{
  char *k;
  khint_t iter;
  khash_t(sym2info) * db;
  int missing;
  struct ipft_syminfo *v;

  k = strdup(name);
  if (k == NULL) {
    return -1;
  }

  v = (struct ipft_syminfo *)malloc(sizeof(*v));
  if (v == NULL) {
    return -1;
  }

  memcpy(v, sinfo, sizeof(*v));

  db = ((struct ipft_symsdb *)sdb)->sym2info;

  iter = kh_put(sym2info, db, k, &missing);
  if (!missing) {
    /* Already exists */
    return -2;
  }

  kh_value(db, iter) = v;

  return 0;
}

int
symsdb_get_sym2info(struct ipft_symsdb *sdb, char *name,
                    struct ipft_syminfo **sinfop)
{
  khint_t iter;
  khash_t(sym2info) * db;

  db = ((struct ipft_symsdb *)sdb)->sym2info;

  iter = kh_get(sym2info, db, name);
  if (iter == kh_end(db)) {
    return -1;
  }

  *sinfop = kh_value(db, iter);

  return 0;
}

int
symsdb_sym2info_foreach(struct ipft_symsdb *sdb,
                        int (*cb)(const char *, struct ipft_syminfo *, void *),
                        void *arg)
{
  int error;
  const char *k;
  struct ipft_syminfo *v;

  kh_foreach(
      sdb->sym2info, k, v, error = cb(k, v, arg);
      if (error == -1) { return -1; })

      return 0;
}

static int
symsdb_put_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char *sym)
{
  char *v;
  int missing;
  khint_t iter;
  khash_t(addr2sym) * db;

  v = strdup(sym);
  if (v == NULL) {
    return -1;
  }

  db = ((struct ipft_symsdb *)sdb)->addr2sym;

  iter = kh_put(addr2sym, db, addr, &missing);
  if (!missing) {
    return -1;
  }

  kh_value(db, iter) = v;

  return 0;
}

int
symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp)
{
  khint_t iter;
  khash_t(addr2sym) * db;

  db = ((struct ipft_symsdb *)sdb)->addr2sym;

  iter = kh_get(addr2sym, db, addr);
  if (iter == kh_end(db)) {
    *symp = "(unknown)";
    return 0;
  }

  *symp = kh_value(db, iter);

  return 0;
}

/*
 * Took from bcc (https://github.com/iovisor/bcc)
 */
#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
const unsigned long long kernel_addr_space = 0x00ffffffffffffff;
#else
const unsigned long long kernel_addr_space = 0x0;
#endif

/*
 * Record the mapping of kernel functions and their addresses
 */
static int
kallsyms_fill_addr2sym(struct ipft_symsdb *sdb)
{
  FILE *f;
  int error;
  uint64_t addr;
  char line[2048];
  char *symname, *endsym;
  struct ipft_syminfo *si;

  f = fopen("/proc/kallsyms", "r");
  if (f == NULL) {
    perror("fopen");
    return -1;
  }

  if (geteuid() != 0) {
    fprintf(
        stderr,
        "Non-root users cannot read address info. Please execute with root.\n");
    return -1;
  }

  while (fgets(line, sizeof(line), f)) {
    addr = strtoull(line, &symname, 16);
    if (addr == 0 || addr == ULLONG_MAX) {
      continue;
    }

    if (addr < kernel_addr_space) {
      continue;
    }

    symname++;

    // Ignore data symbols
    if (*symname == 'b' || *symname == 'B' || *symname == 'd' ||
        *symname == 'D' || *symname == 'r' || *symname == 'R') {
      continue;
    }

    symname += 2;
    endsym = symname;
    while (*endsym && !isspace(*endsym)) {
      endsym++;
    }

    *endsym = '\0';

    /*
     * IP points to 1byte after than the address kallsyms reports
     */
    addr += 1;

    /*
     * Only add the symbols which are used
     */
    error = symsdb_get_sym2info(sdb, symname, &si);
    if (error == -1) {
      continue;
    }

    /*
     * This shouldn't fail
     */
    error = symsdb_put_addr2sym(sdb, addr, symname);
    if (error == -1) {
      fprintf(stderr, "symsdb_put_addr2sym failed\n");
      return -1;
    }
  }

  fclose(f);

  return 0;
}

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

    /*
     * Find the type "struct sk_buff *" from function arguments
     * and record its position.
     */
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

/*
 * Finds the kernel functions which take struct sk_buff
 * as an argument and record the position of the argument.
 */
static int
kernel_btf_fill_sym2info(struct ipft_symsdb *sdb)
{
  FTS *fts;
  FTSENT *f;
  int error;
  struct btf *btf, *vmlinux_btf;
  char *const path_argv[] = {"/sys/kernel/btf", NULL};

  /*
   * First, explore the functions in vmlinux BTF.
   * libbpf_find_kernel_btf supports finding the
   * BTF from both of the ELF files on disk and
   * sysfs.
   */
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
   * module BTFs. Unlike vmlinux BTF, libbpf doesn't
   * privide the way to load the kernel module BTFs from
   * ELF files on the disk. Currently, we don't support
   * it because it's difficult to implement it correctly.
   */
  if (access("/sys/kernel/btf/vmlinux", R_OK) != 0) {
    return 0;
  }

  /*
   * Iterate over the files under /sys/kernel/btf to find
   * kernel module BTFs.
   */
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

int
symsdb_create(struct ipft_symsdb **sdbp)
{
  int error;
  struct ipft_symsdb *sdb;

  sdb = (struct ipft_symsdb *)malloc(sizeof(*sdb));
  if (sdb == NULL) {
    perror("malloc");
    return -1;
  }

  sdb->sym2info = kh_init(sym2info);
  if (sdb->sym2info == NULL) {
    perror("kh_init");
    return -1;
  }

  error = kernel_btf_fill_sym2info(sdb);
  if (error == -1) {
    fprintf(stderr, "kernel_btf_fill_sym2info failed\n");
    return -1;
  }

  sdb->addr2sym = kh_init(addr2sym);
  if (sdb->addr2sym == NULL) {
    perror("kh_init");
    return -1;
  }

  error = kallsyms_fill_addr2sym(sdb);
  if (error == -1) {
    fprintf(stderr, "kallsyms_fill_addr2sym failed\n");
    return -1;
  }

  *sdbp = (struct ipft_symsdb *)sdb;

  return 0;
}
