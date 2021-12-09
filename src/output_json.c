#include <stdio.h>
#include <stdlib.h>

#include "ipft.h"

/*
 * Line-oriented JSON stream output
 */

struct json_output {
  struct ipft_output base;
};

static int
print_script_output(const char *k, size_t klen, const char *v, size_t vlen)
{
  printf(",\"%.*s\":\"%.*s\"", (int)klen, k, (int)vlen, v);
  return 0;
}

static int
json_output_on_event(struct ipft_output *_out, struct ipft_event *e)
{
  int error;
  char *name;
  struct json_output *out = (struct json_output *)_out;

  error = symsdb_get_addr2sym(out->base.sdb, e->faddr, &name);
  if (error == -1) {
    fprintf(stderr, "Failed to resolve the symbol from address\n");
    return -1;
  }

  printf("{\"packet_id\":\"%p\",\"timestamp\":%zu,\"processor_id\":%u,"
         "\"function\":\"%s\"",
         (void *)e->packet_id, e->tstamp, e->processor_id, name);

  if (out->base.script) {
    error = script_exec_dump(out->base.script, e->data, sizeof(e->data),
                             print_script_output);
    if (error == -1) {
      return -1;
    }
  }

  printf("}\n");

  fflush(stdout);

  return 0;
}

static int
json_output_post_trace(__unused struct ipft_output *_out)
{
  return 0;
}

int
json_output_create(struct ipft_output **outp)
{
  struct json_output *out;

  out = malloc(sizeof(*out));
  if (out == NULL) {
    perror("malloc");
    return -1;
  }

  out->base.on_event = json_output_on_event;
  out->base.post_trace = json_output_post_trace;

  *outp = (struct ipft_output *)out;

  return 0;
}
