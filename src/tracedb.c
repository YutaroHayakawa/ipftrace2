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

#include "ipft.h"

static void
dtor(void *p)
{
  free(*(struct ipft_sample **)p);
}

KLIST_INIT(trace_list, struct ipft_sample *, dtor)
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
tracedb_put_trace(struct ipft_tracedb *tdb, struct ipft_sample *_s)
{
  int ret;
  khint_t iter;
  struct ipft_sample *s;
  klist_t(trace_list) * l;

  s = malloc(sizeof(*s));
  if (s == NULL) {
    perror("malloc");
    return -1;
  }

  memcpy(s, _s, sizeof(*s));

  iter = kh_put(trace, tdb->trace, s->skb_addr, &ret);
  if (ret == -1) {
    fprintf(stderr, "Cannot allocate tracedb element\n");
    return -1;
  } else if (ret == 0) {
    l = kh_value(tdb->trace, iter);
    *kl_pushp(trace_list, l) = s;
  } else {
    l = kl_init(trace_list);
    if (l == NULL) {
      perror("kl_init");
      return -1;
    }
    *kl_pushp(trace_list, l) = s;
    kh_value(tdb->trace, iter) = l;
  }

  return 0;
}

static int
compare_tstamp(const void *_s1, const void *_s2)
{
  const struct ipft_sample *s1 = *(struct ipft_sample **)_s1;
  const struct ipft_sample *s2 = *(struct ipft_sample **)_s2;
  if (s1->tstamp < s2->tstamp) {
    return -1;
  } else {
    return 1;
  }
}

void
tracedb_dump(struct ipft_tracedb *tdb, struct ipft_symsdb *sdb,
             struct ipft_script *script)
{
  int error;
  char *name;
  klist_t(trace_list) * l;
  kliter_t(trace_list) * iter;
  struct ipft_sample *s, **sarray;

  kh_foreach_value(
      tdb->trace, l, printf("===\n");

      /*
       * We need to put trace data to array just to use qsort(3)
       * this is not so efficient way, but works well.
       */
      sarray = calloc(l->size, sizeof(sarray));
      if (sarray == NULL) {
        perror("calloc");
        return;
      }

      uint32_t count = 0;
      for (iter = kl_begin(l); iter != kl_end(l); iter = kl_next(iter)) {
        sarray[count] = kl_val(iter);
        count++;
      }

      /*
       * Order trace by timestamp. They are not always orderd since they
       * can be collected with different perf ring.
       */
      qsort(sarray, count, sizeof(*sarray), compare_tstamp);

      for (uint32_t i = 0; i < count; i++) {
        s = sarray[i];

        error = symsdb_get_addr2sym(sdb, s->faddr, &name);
        if (error == -1) {
          fprintf(stderr, "Failed to resolve the symbol from address\n");
          free(sarray);
          return;
        }

        if (script != NULL) {
          printf("%zu %03u %32.32s %s\n", s->tstamp, s->processor_id, name,
                 script_exec_dump(script, s->data, sizeof(s->data)));
        } else {
          printf("%zu %03u %32.32s\n", s->tstamp, s->processor_id, name);
        }
      }

      free(sarray);)
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
    return -1;
  }

  *tdbp = tdb;

  return 0;
}
