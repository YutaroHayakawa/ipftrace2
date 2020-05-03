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

size_t symsdb_get_sym2info_total(struct ipft_symsdb *sdb) {
  return kh_size(sdb->sym2info);
}

int symsdb_put_sym2info(struct ipft_symsdb *sdb, char *name,
                        struct ipft_syminfo *sinfo) {
  char *k;
  khint_t iter;
  khash_t(sym2info) * db;
  int error = 0, missing;
  struct ipft_syminfo *v;

  k = strdup(name);
  if (k == NULL) {
    return -1;
  }

  v = (struct ipft_syminfo *)malloc(sizeof(*v));
  if (v == NULL) {
    error = -1;
    goto err0;
  }

  memcpy(v, sinfo, sizeof(*v));

  db = ((struct ipft_symsdb *)sdb)->sym2info;

  iter = kh_put(sym2info, db, k, &missing);
  if (missing) {
    kh_value(db, iter) = v;
  } else {
    goto err1;
  }

  return 0;

err1:
  free(v);
err0:
  free(k);
  return error;
}

int symsdb_get_sym2info(struct ipft_symsdb *sdb, char *name,
                        struct ipft_syminfo **sinfop) {
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

void symsdb_release_all_sym2info(struct ipft_symsdb *sdb) {
  const char *k;
  struct ipft_syminfo *v;
  kh_foreach(sdb->sym2info, k, v, free((char *)k); free(v););
}

int symsdb_sym2info_foreach(struct ipft_symsdb *sdb,
                            int (*cb)(const char *, struct ipft_syminfo *,
                                      void *),
                            void *arg) {
  int error;
  const char *k;
  struct ipft_syminfo *v;

  kh_foreach(
      sdb->sym2info, k, v, error = cb(k, v, arg);
      if (error == -1) { return -1; })

      return 0;
}

int symsdb_put_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char *sym) {
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
  if (missing) {
    kh_value(db, iter) = v;
  } else {
    goto err0;
  }

  return 0;

err0:
  free(v);
  return -1;
}

int symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp) {
  khint_t iter;
  khash_t(addr2sym) * db;

  db = ((struct ipft_symsdb *)sdb)->addr2sym;

  iter = kh_get(addr2sym, db, addr);
  if (iter == kh_end(db)) {
    return -1;
  }

  *symp = kh_value(db, iter);

  return 0;
}

void symsdb_release_all_addr2sym(struct ipft_symsdb *sdb) {
  char *v;
  kh_foreach_value(sdb->addr2sym, v, free(v);)
}

int symsdb_create(struct ipft_symsdb **sdbp) {
  struct ipft_symsdb *sdb;

  sdb = (struct ipft_symsdb *)malloc(sizeof(*sdb));
  if (sdb == NULL) {
    perror("malloc");
    return -1;
  }

  sdb->sym2info = kh_init(sym2info);
  if (sdb->sym2info == NULL) {
    perror("kh_init");
    goto err0;
  }

  sdb->addr2sym = kh_init(addr2sym);
  if (sdb->addr2sym == NULL) {
    perror("kh_init");
    goto err1;
  }

  *sdbp = (struct ipft_symsdb *)sdb;

  return 0;

err1:
  kh_destroy(sym2info, sdb->sym2info);
err0:
  free(sdb);
  return -1;
}

void symsdb_destroy(struct ipft_symsdb *sdb) {
  symsdb_release_all_sym2info(sdb);
  kh_destroy(sym2info, sdb->sym2info);
  symsdb_release_all_addr2sym(sdb);
  kh_destroy(addr2sym, sdb->addr2sym);
  free(sdb);
}
