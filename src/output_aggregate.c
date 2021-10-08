/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>

#include "khash.h"
#include "klist.h"

#include "ipft.h"

/*
 * Aggregate output with on-memory trace store
 */

static void
dtor(void *p)
{
  free(*(struct ipft_trace **)p);
}

KLIST_INIT(trace_list, struct ipft_trace *, dtor)
KHASH_MAP_INIT_INT64(trace, klist_t(trace_list) *)

struct aggregate_output {
  struct ipft_output base;
  khash_t(trace) * trace;
  size_t ntraces;
};

static int
aggregate_output_on_trace(struct ipft_output *_out, struct ipft_trace *_t)
{
  int ret;
  khint_t iter;
  struct ipft_trace *t;
  klist_t(trace_list) * l;
  struct aggregate_output *out = (struct aggregate_output *)_out;

  t = malloc(sizeof(*t));
  if (t == NULL) {
    perror("malloc");
    return -1;
  }

  memcpy(t, _t, sizeof(*t));

  /* Put trace to trace store */
  iter = kh_put(trace, out->trace, t->skb_addr, &ret);
  if (ret == -1) {
    fprintf(stderr, "Failed to put trace to store\n");
    return -1;
  } else if (ret == 0) {
    l = kh_value(out->trace, iter);
    *kl_pushp(trace_list, l) = t;
  } else {
    l = kl_init(trace_list);
    if (l == NULL) {
      perror("kl_init");
      return -1;
    }
    *kl_pushp(trace_list, l) = t;
    kh_value(out->trace, iter) = l;
  }

  /* Update the status on screen */
  fprintf(stderr, "\rGot %zu traces", out->ntraces++);
  fflush(stderr);

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

static int
print_script_output(const char *k, size_t klen, const char *v, size_t vlen)
{
  printf("%.*s: %.*s ", (int)klen, k, (int)vlen, v);
  return 0;
}

static int
aggregate_output_post_trace(struct ipft_output *_out)
{
  int error;
  char *name;
  klist_t(trace_list) * l;
  kliter_t(trace_list) * iter;
  struct ipft_trace *t, **tarray;
  struct aggregate_output *out = (struct aggregate_output *)_out;

  printf("\n");

  kh_foreach_value(
      out->trace, l, printf("===\n");

      /*
       * We need to put trace data to array just to use qsort(3)
       * this is not so efficient way, but works well.
       */
      tarray = calloc(l->size, sizeof(*tarray));
      if (tarray == NULL) {
        perror("calloc");
        return -1;
      }

      uint32_t count = 0;
      for (iter = kl_begin(l); iter != kl_end(l); iter = kl_next(iter)) {
        tarray[count] = kl_val(iter);
        count++;
      }

      /*
       * Order trace by timestamp. They are not always orderd since they
       * can be collected with different perf ring.
       */
      qsort(tarray, count, sizeof(*tarray), compare_tstamp);

      for (uint32_t i = 0; i < count; i++) {
        t = tarray[i];

        error = symsdb_get_addr2sym(out->base.sdb, t->faddr, &name);
        if (error == -1) {
          fprintf(stderr, "Failed to resolve the symbol from address\n");
          free(tarray);
          return -1;
        }

        if (out->base.script != NULL) {
          /* Print basic data */
          printf("%zu %03u %32.32s ( ", t->tstamp, t->processor_id, name);

          /* Execute script and print results */
          error = script_exec_dump(out->base.script, t->data, sizeof(t->data),
                                   print_script_output);
          if (error == -1) {
            return -1;
          }

          printf(")\n");
        } else {
          printf("%zu %03u %32.32s\n", t->tstamp, t->processor_id, name);
        }
      }

      free(tarray);)

      return 0;
}

int
aggregate_output_create(struct ipft_output **outp)
{
  struct aggregate_output *out;

  out = malloc(sizeof(*out));
  if (out == NULL) {
    perror("malloc");
    return -1;
  }

  out->trace = kh_init(trace);
  if (out->trace == NULL) {
    perror("kh_init");
    return -1;
  }

  out->ntraces = 0;
  out->base.on_trace = aggregate_output_on_trace;
  out->base.post_trace = aggregate_output_post_trace;

  *outp = (struct ipft_output *)out;

  return 0;
}
