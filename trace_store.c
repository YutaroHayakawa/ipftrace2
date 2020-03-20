#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "khash.h"
#include "klist.h"

#include "ipftrace.h"

#define assert_malloc(_ptr) do { \
  if (_ptr == NULL) { \
    fprintf(stderr, "Cannot allocate memory\n"); \
    exit(EXIT_FAILURE); \
  } \
} while (0)

static void
dtor(__unused void *p)
{
  return;
}

KLIST_INIT(trace_list, struct ipft_trace *, dtor)
KHASH_MAP_INIT_INT64(trace, klist_t(trace_list ) *)

struct ipft_trace_store {
  khash_t(trace) *ts;
};

size_t
ipft_trace_total(struct ipft_trace_store *ts)
{
  return kh_size(ts->ts);
}

int
ipft_trace_add(struct ipft_trace_store *ts, struct ipft_trace *t)
{
  int ret;
  khint_t iter;
  klist_t(trace_list) *l;

  iter = kh_put(trace, ts->ts, t->skb_addr, &ret);
  if (ret == 0) {
    l = kh_value(ts->ts, iter);
    *kl_pushp(trace_list, l) = t;
  } else {
    l = kl_init(trace_list);
    assert_malloc(l);
    *kl_pushp(trace_list, l) = t;
    kh_value(ts->ts, iter) = l;
  }

  return 0;
}

void
ipft_trace_dump(struct ipft_trace_store *ts, struct ipft_symsdb *sdb, FILE *f)
{
  char *name;
  uint32_t count = 0;
  __unused uint64_t skb_addr;
  struct ipft_trace *t;
  klist_t(trace_list) *l;
  kliter_t(trace_list) *iter;

  kh_foreach(ts->ts, skb_addr, l,
    count++;
    fprintf(f, "Captured Packet %u\n", count);
    for (iter = kl_begin(l); iter != kl_end(l); iter = kl_next(iter)) {
      t = kl_val(iter);
      name = ipft_symsdb_get_sym(sdb, t->faddr);
      fprintf(f, "  %zu %s\n", t->tstamp, name);
    }
  );
}

int
ipft_trace_store_create(struct ipft_trace_store **tsp)
{
  struct ipft_trace_store *ret;

  ret = (struct ipft_trace_store *)malloc(sizeof(*ret));
  assert_malloc(ret);

  ret->ts = kh_init(trace);
  assert_malloc(ret->ts);

  *tsp = ret;

  return 0;
}

/*
int
main(void)
{
  int error;
  struct ipft_trace_store *ts;
  struct ipft_trace traces[] = {
    { 1111, 22221 },
    { 1112, 22222 },
    { 1113, 22223 },
    { 1114, 22224 },
    { 1115, 22225 },
  };

  error = ipft_trace_store_create(&ts);
  if (error != 0) {
    fprintf(stderr, "ipft_trace_store_create: %s\n", strerror(error));
    return EXIT_FAILURE;
  }

  ipft_trace_add(ts, 0, &traces[0]);
  ipft_trace_add(ts, 1, &traces[1]);
  ipft_trace_add(ts, 2, &traces[2]);
  ipft_trace_add(ts, 3, &traces[3]);
  ipft_trace_add(ts, 0, &traces[4]);

  ipft_trace_dump(ts);

  return EXIT_SUCCESS;
}
*/
