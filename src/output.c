#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipftrace.h"

int
output_create(struct ipft_output **outp, const char *type,
    struct ipft_symsdb *sdb)
{
  int error;
  struct ipft_output *out;

  if (strcmp(type, "aggregate") == 0) {
    error = aggregate_output_create(&out);
  } else if (strcmp(type, "stream") == 0) {
    error = stream_output_create(&out);
  } else {
    fprintf(stderr, "Unsupported output type %s\n", type);
    return -1;
  }

  if (error == -1) {
    fprintf(stderr, "Failed to create output\n");
    return -1;
  }

  out->sdb = sdb;

  *outp = out;

  return 0;
}

int
output_on_trace(struct ipft_output *out, struct ipft_trace *t)
{
  return out->on_trace(out, t);
}

int
output_post_trace(struct ipft_output *out)
{
  return out->post_trace(out);
}
