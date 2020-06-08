/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "khash.h"
#include "klist.h"

#include "ipftrace.h"

static void
dtor(void *p)
{
  free(*(struct ipft_trace **)p);
}

KLIST_INIT(trace_list, struct ipft_trace *, dtor)
KHASH_MAP_INIT_INT64(trace, klist_t(trace_list) *)

struct ipft_tracedb {
  khash_t(trace) * trace;
};

size_t
tracedb_get_total(struct ipft_tracedb *tdb)
{
  return kh_size(tdb->trace);
}

int
tracedb_put_trace(struct ipft_tracedb *tdb, struct ipft_trace *t)
{
  int ret;
  khint_t iter;
  klist_t(trace_list) * l;

  iter = kh_put(trace, tdb->trace, t->skb_addr, &ret);
  if (ret == -1) {
    fprintf(stderr, "Cannot allocate tracedb element\n");
    exit(EXIT_FAILURE);
  } else if (ret == 0) {
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

static int
compare_tstamp(const void *_t1, const void *_t2)
{
  const struct ipft_trace *t1 = *(struct ipft_trace **)_t1;
  const struct ipft_trace *t2 = *(struct ipft_trace **)_t2;
  if (t1->tstamp < t2->tstamp) {
    return -1;
  } else {
    return 1;
  }
}

void
tracedb_dump(struct ipft_tracedb *tdb, struct ipft_symsdb *sdb,
             char *(*cb)(uint8_t *, size_t, void *), void *arg)
{
  int error;
  char *name, *dump;
  klist_t(trace_list) * l;
  kliter_t(trace_list) * iter;
  struct ipft_trace *t, **tarray;

  kh_foreach_value(tdb->trace, l,
      printf("===\n");

      /*
       * We need to put trace data to array just to use qsort(3)
       * this is not so efficient way, but works well.
       */
      tarray = calloc(l->size, sizeof(*tarray));
      if (tarray == NULL) {
        perror("calloc");
        return;
      }

      uint32_t count = 0;
      for (iter = kl_begin(l); iter != kl_end(l); iter = kl_next(iter)) {
        tarray[count] = kl_val(iter);
        count++;
      }

      qsort(tarray, count, sizeof(*tarray), compare_tstamp);

      for (uint32_t i = 0; i < count; i++) {
        t = tarray[i];

        error = symsdb_get_addr2sym(sdb, t->faddr, &name);
        if (error == -1) {
          fprintf(stderr, "Failed to resolve the symbol from address\n");
          free(tarray);
          return;
        }

        if (cb != NULL) {
          dump = cb(t->data, sizeof(t->data), arg);
        } else {
          dump = NULL;
        }

        if (dump == NULL) {
          printf("%zu %04u %32.32s\n", t->tstamp, t->processor_id, name);
        } else {
          printf("%zu %04u %32.32s %s\n", t->tstamp, t->processor_id, name,
                 dump);
          free(dump);
        }
      }

      free(tarray);
    )
}

int
tracedb_create(struct ipft_tracedb **tdbp)
{
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

void
tracedb_destroy(struct ipft_tracedb *tdb)
{
  klist_t(trace_list) * v;
  kh_foreach_value(tdb->trace, v, kl_destroy(trace_list, v);)
      kh_destroy(trace, tdb->trace);
  free(tdb);
}
