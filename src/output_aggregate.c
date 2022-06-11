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
  free(*(struct ipft_event **)p);
}

KLIST_INIT(trace_list, struct ipft_event *, dtor)
KHASH_MAP_INIT_INT64(trace, klist_t(trace_list) *)

struct aggregate_output {
  struct ipft_output base;
  khash_t(trace) * trace;
  size_t ntraces;
};

static int
aggregate_output_on_event(struct ipft_output *_out, struct ipft_event *_e)
{
  int ret;
  khint_t iter;
  struct ipft_event *e;
  klist_t(trace_list) * l;
  struct aggregate_output *out = (struct aggregate_output *)_out;

  e = malloc(sizeof(*e));
  if (e == NULL) {
    perror("malloc");
    return -1;
  }

  memcpy(e, _e, sizeof(*e));

  /* Put trace to trace store */
  iter = kh_put(trace, out->trace, e->packet_id, &ret);
  if (ret == -1) {
    fprintf(stderr, "Failed to put trace to store\n");
    return -1;
  } else if (ret == 0) {
    l = kh_value(out->trace, iter);
    *kl_pushp(trace_list, l) = e;
  } else {
    l = kl_init(trace_list);
    if (l == NULL) {
      perror("kl_init");
      return -1;
    }
    *kl_pushp(trace_list, l) = e;
    kh_value(out->trace, iter) = l;
  }

  /* Update the status on screen */
  fprintf(stderr, "\rGot %zu traces", out->ntraces++);
  fflush(stderr);

  return 0;
}

static int
compare_tstamp(const void *_e1, const void *_e2)
{
  const struct ipft_event *e1 = *(struct ipft_event **)_e1;
  const struct ipft_event *e2 = *(struct ipft_event **)_e2;
  if (e1->tstamp < e2->tstamp) {
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
dump_function(struct aggregate_output *out, struct ipft_event **earray,
              uint32_t count)
{
  int error;
  char *symname;
  struct ipft_event *e;

  for (uint32_t i = 0; i < count; i++) {
    e = earray[i];

    error = symsdb_get_symname_by_addr(out->base.sdb, e->faddr, &symname);
    if (error == -1) {
      fprintf(stderr, "symsdb_get_symname_by_addr failed\n");
      return -1;
    }

    if (out->base.script != NULL) {
      /* Print basic data */
      printf("%-20zu %03u %32.32s ( ", e->tstamp, e->processor_id, symname);

      /* Execute script and print results */
      error = script_exec_decode(out->base.script, e->data, sizeof(e->data),
                                 print_script_output);
      if (error == -1) {
        return -1;
      }

      printf(")\n");
    } else {
      printf("%-20zu %03u %32.32s\n", e->tstamp, e->processor_id, symname);
    }
  }

  return 0;
}

static int
dump_function_graph(struct aggregate_output *out, struct ipft_event **earray,
                    uint32_t count)
{
  int error;
  char *symname;
  struct ipft_event *e;

  uint32_t indent = 0;
  for (uint32_t i = 0; i < count; i++) {
    e = earray[i];

    error = symsdb_get_symname_by_addr(out->base.sdb, e->faddr, &symname);
    if (error == -1) {
      fprintf(stderr, "Failed to resolve the symbol from address\n");
      return -1;
    }

    char s[64] = {0};
    if (!e->is_return) {
      sprintf(s, "%-*s%s() {", indent * 2, "", symname);

      if (out->base.script != NULL) {
        /* Print basic data */
        printf("%-20zu %03u %-64.64s ( ", e->tstamp, e->processor_id, s);

        /* Execute script and print results */
        error = script_exec_decode(out->base.script, e->data, sizeof(e->data),
                                   print_script_output);
        if (error == -1) {
          return -1;
        }

        printf(")\n");
      } else {
        printf("%-20zu %03u %-64.64s\n", e->tstamp, e->processor_id, s);
      }

      /*
       * When there is a mismatch between entry and exit trace, overflow
       * happens.
       */
      if (indent != UINT32_MAX) {
        indent++;
      }
    } else {
      /*
       * When there is a mismatch between entry and exit trace, underflow
       * happens.
       */
      if (indent != 0) {
        indent--;
      }

      sprintf(s, "%-*s}", indent * 2, "");

      if (out->base.script != NULL) {
        /* Print basic data */
        printf("%-20zu %03u %-64.64s ( ", e->tstamp, e->processor_id, s);

        /* Execute script and print results */
        error = script_exec_decode(out->base.script, e->data, sizeof(e->data),
                                   print_script_output);
        if (error == -1) {
          return -1;
        }

        printf(")\n");
      } else {
        printf("%-20zu %03u %-64.64s\n", e->tstamp, e->processor_id, s);
      }
    }
  }

  return 0;
}

static int
aggregate_output_post_trace(struct ipft_output *_out)
{
  int error;
  klist_t(trace_list) * l;
  kliter_t(trace_list) * iter;
  struct ipft_event **earray;
  struct aggregate_output *out = (struct aggregate_output *)_out;

  printf("\n");

  printf("%-20s %3.3s %32.32s\n", "Timestamp", "CPU", "Function");
  kh_foreach_value(
      out->trace, l, printf("===\n");

      /*
       * We need to put trace data to array just to use qsort(3)
       * this is not so efficient way, but works well.
       */
      earray = calloc(l->size, sizeof(*earray));
      if (earray == NULL) {
        perror("calloc");
        return -1;
      }

      uint32_t count = 0;
      for (iter = kl_begin(l); iter != kl_end(l); iter = kl_next(iter)) {
        earray[count] = kl_val(iter);
        count++;
      }

      /*
       * Order trace by timestamp. They are not always orderd since they
       * can be collected with different perf ring.
       */
      qsort(earray, count, sizeof(*earray), compare_tstamp);

      if (out->base.tracer == IPFT_TRACER_FUNCTION) {
        error = dump_function(out, earray, count);
        if (error != 0) {
          fprintf(stderr, "dump_function failed\n");
          return -1;
        }
      } else if (out->base.tracer == IPFT_TRACER_FUNCTION_GRAPH) {
        error = dump_function_graph(out, earray, count);
        if (error != 0) {
          fprintf(stderr, "dump_function_graph failed\n");
          return -1;
        }
      } else {
        fprintf(stderr, "Unexpected tracer ID %d\n", out->base.tracer);
        return -1;
      }

      free(earray);)

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
  out->base.on_event = aggregate_output_on_event;
  out->base.post_trace = aggregate_output_post_trace;

  *outp = (struct ipft_output *)out;

  return 0;
}
