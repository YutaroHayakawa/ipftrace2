#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <linux/bpf.h>

#include "ipft.h"

static int
print_sym(const char *name, __unused struct ipft_syminfo *sinfo, void *data)
{
  struct ipft_regex *re = (struct ipft_regex *)data;

  if (regex_match(re, name)) {
    printf("%s\n", name);
  }

  return 0;
}

int
list_functions(struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_regex *re;
  struct ipft_symsdb *sdb;

  error = regex_create(&re, opt->regex);
  if (error == -1) {
    fprintf(stderr, "regex_create failed\n");
    return -1;
  }

  error = symsdb_create(&sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to initialize symsdb\n");
    return -1;
  }

  error = kernel_btf_fill_sym2info(sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to fill sym2info\n");
    return -1;
  }

  error = symsdb_sym2info_foreach(sdb, print_sym, re);
  if (error == -1) {
    fprintf(stderr, "Failed to traverse sym2info\n");
    return -1;
  }

  return 0;
}
