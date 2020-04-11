#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "khash.h"
#include "klist.h"

#include "ipftrace.h"

static void dtor(void *p) { free(*(struct ipft_trace **)p); }

KLIST_INIT(trace_list, struct ipft_trace *, dtor)
KHASH_MAP_INIT_INT64(trace, klist_t(trace_list) *)

struct ipft_tracedb {
  khash_t(trace) * trace;
};

size_t tracedb_get_total(struct ipft_tracedb *tdb) {
  return kh_size(tdb->trace);
}

int tracedb_put_trace(struct ipft_tracedb *tdb, struct ipft_trace *t) {
  int ret;
  khint_t iter;
  klist_t(trace_list) * l;

  iter = kh_put(trace, tdb->trace, t->skb_addr, &ret);
  if (ret == 0) {
    l = kh_value(tdb->trace, iter);
    *kl_pushp(trace_list, l) = t;
  } else {
    l = kl_init(trace_list);
    if (l == NULL) {
      perror("kl_init");
      return -1;
    }
    *kl_pushp(trace_list, l) = t;
    kh_value(tdb->trace, iter) = l;
  }

  return 0;
}

void tracedb_dump(struct ipft_tracedb *tdb, struct ipft_symsdb *sdb, FILE *f) {
  int error;
  char *name;
  uint32_t count = 0;
  struct ipft_trace *t;
  klist_t(trace_list) * l;
  kliter_t(trace_list) * iter;

  kh_foreach_value(
      tdb->trace, l, count++; fprintf(f, "sk_buff %u\n", count);
      for (iter = kl_begin(l); iter != kl_end(l); iter = kl_next(iter)) {
        t = kl_val(iter);
        error = symsdb_get_addr2sym(sdb, t->faddr, &name);
        if (error == -1) {
          fprintf(stderr, "Failed to resolve the symbol from address\n");
          return;
        }
        fprintf(f, "  %zu %04u %s\n", t->tstamp, t->processor_id, name);
      })
}

int tracedb_create(struct ipft_tracedb **tdbp) {
  struct ipft_tracedb *tdb;

  tdb = (struct ipft_tracedb *)malloc(sizeof(*tdb));
  if (tdb == NULL) {
    perror("malloc");
    return -1;
  }

  tdb->trace = kh_init(trace);
  if (tdb == NULL) {
    perror("kh_init");
    goto err0;
  }

  *tdbp = tdb;

  return 0;

err0:
  free(tdb);
  return -1;
}

void tracedb_destroy(struct ipft_tracedb *tdb) {
  klist_t(trace_list) * v;
  kh_foreach_value(tdb->trace, v, kl_destroy(trace_list, v);)
      kh_destroy(trace, tdb->trace);
  free(tdb);
}
