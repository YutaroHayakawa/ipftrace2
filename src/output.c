#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipft.h"

const char *
get_output_name_by_id(enum ipft_outputs id)
{
  switch (id) {
  case IPFT_OUTPUT_AGGREGATE:
    return "aggregate";
  case IPFT_OUTPUT_JSON:
    return "json";
  default:
    return NULL;
  }
}

enum ipft_outputs
get_output_id_by_name(const char *name)
{
  if (strcmp(name, "aggregate") == 0) {
    return IPFT_OUTPUT_AGGREGATE;
  }

  if (strcmp(name, "json") == 0) {
    return IPFT_OUTPUT_JSON;
  }

  return IPFT_OUTPUT_UNSPEC;
}

int
output_create(struct ipft_output **outp, enum ipft_outputs output,
              struct ipft_symsdb *sdb, struct ipft_script *script,
              enum ipft_tracers tracer)
{
  int error;
  struct ipft_output *out;

  switch (output) {
  case IPFT_OUTPUT_AGGREGATE:
    error = aggregate_output_create(&out);
    break;
  case IPFT_OUTPUT_JSON:
    error = json_output_create(&out);
    break;
  default:
    fprintf(stderr, "Unsupported output ID %d\n", output);
    return -1;
  }

  if (error == -1) {
    fprintf(stderr, "Failed to create output\n");
    return -1;
  }

  out->tracer = tracer;
  out->sdb = sdb;
  out->script = script;

  *outp = out;

  return 0;
}

int
output_on_trace(struct ipft_output *out, struct ipft_event *e)
{
  return out->on_event(out, e);
}

int
output_post_trace(struct ipft_output *out)
{
  return out->post_trace(out);
}
