/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stdio.h>
#include <stdlib.h>

#include "ipft.h"

/*
 * Line-oriented text stream output
 */

struct stream_output {
  struct ipft_output base;
};

static int
stream_output_on_trace(struct ipft_output *_out, struct ipft_trace *t)
{
  int error;
  char *name;
  struct stream_output *out = (struct stream_output *)_out;

  error = symsdb_get_addr2sym(out->base.sdb, t->faddr, &name);
  if (error == -1) {
    fprintf(stderr, "Failed to resolve the symbol from address\n");
    return -1;
  }

  printf("%p %zu %03u %s\n", (void *)t->skb_addr, t->tstamp, t->processor_id,
         name);

  fflush(stdout);

  return 0;
}

static int
stream_output_post_trace(__unused struct ipft_output *_out)
{
  return 0;
}

int
stream_output_create(struct ipft_output **outp)
{
  struct stream_output *out;

  out = malloc(sizeof(*out));
  if (out == NULL) {
    perror("malloc");
    return -1;
  }

  out->base.on_trace = stream_output_on_trace;
  out->base.post_trace = stream_output_post_trace;

  *outp = (struct ipft_output *)out;

  return 0;
}
