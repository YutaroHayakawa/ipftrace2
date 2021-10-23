#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipft.h"

int
output_create(struct ipft_output **outp, const char *type,
              struct ipft_symsdb *sdb, struct ipft_script *script)
{
  int error;
  struct ipft_output *out;

  if (strcmp(type, "aggregate") == 0) {
    error = aggregate_output_create(&out);
  } else if (strcmp(type, "json") == 0) {
    error = json_output_create(&out);
  } else {
    fprintf(stderr, "Unsupported output type %s\n", type);
    return -1;
  }

  if (error == -1) {
    fprintf(stderr, "Failed to create output\n");
    return -1;
  }

  out->sdb = sdb;
  out->script = script;

  *outp = out;

  return 0;
}

int
output_on_trace(struct ipft_output *out, struct ipft_event *e)
{
  return out->on_trace(out, e);
}

int
output_post_trace(struct ipft_output *out)
{
  return out->post_trace(out);
}
