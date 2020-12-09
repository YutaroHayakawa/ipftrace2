/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ipftrace.h"
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

int
symsdb_put_sym2info(struct ipft_symsdb *sdb, char *name,
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
    return -1;
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

int
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

int
symsdb_create(struct ipft_symsdb **sdbp)
{
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

  sdb->addr2sym = kh_init(addr2sym);
  if (sdb->addr2sym == NULL) {
    perror("kh_init");
    return -1;
  }

  *sdbp = (struct ipft_symsdb *)sdb;

  return 0;
}
