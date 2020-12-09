/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stdio.h>
#include <stdlib.h>

#include "ipftrace.h"

/*
 * Aggregate output with on-memory tracedb
 */

struct aggregate_output {
  struct ipft_output base;
  struct ipft_tracedb *tdb;
  size_t ntraces;
};

static int
aggregate_output_on_trace(struct ipft_output *_out, struct ipft_trace *t)
{
  struct aggregate_output *out = (struct aggregate_output *)_out;
  fprintf(stderr, "\rGot %zu traces", out->ntraces++);
  fflush(stderr);
  return tracedb_put_trace(out->tdb, t);
}

static char *
dump_trace(uint8_t *data, size_t size, void *arg)
{
  struct ipft_script *script = (struct ipft_script *)arg;
  return script_exec_dump(script, data, size);
}

static int
aggregate_output_post_trace(struct ipft_output *_out)
{
  struct aggregate_output *out = (struct aggregate_output *)_out;
  printf("\n");
  tracedb_dump(out->tdb, out->base.sdb, dump_trace, out->base.script);
  return 0;
}

int
aggregate_output_create(struct ipft_output **outp)
{
  int error;
  struct aggregate_output *out;

  out = malloc(sizeof(*out));
  if (out == NULL) {
    perror("malloc");
    return -1;
  }

  error = tracedb_create(&out->tdb);
  if (error == -1) {
    fprintf(stderr, "tracedb_create failed\n");
    return -1;
  }

  out->ntraces = 0;
  out->base.on_trace = aggregate_output_on_trace;
  out->base.post_trace = aggregate_output_post_trace;

  *outp = (struct ipft_output *)out;

  return 0;
}
