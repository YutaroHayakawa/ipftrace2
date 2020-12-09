#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <linux/bpf.h>

#include "ipftrace.h"

static int
print_sym(const char *name, __unused struct ipft_syminfo *sinfo,
          __unused void *data)
{
  printf("%s\n", name);
  return 0;
}

int
list_functions(void)
{
  int error;
  struct ipft_symsdb *sdb;
  struct ipft_debuginfo *dinfo;

  error = symsdb_create(&sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to initialize symsdb\n");
    return -1;
  }

  error = debuginfo_create(&dinfo);
  if (error == -1) {
    fprintf(stderr, "Error in initializing debuginfo\n");
    return -1;
  }

  error = debuginfo_fill_sym2info(dinfo, sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to fill sym2info\n");
    return -1;
  }

  error = symsdb_sym2info_foreach(sdb, print_sym, NULL);
  if (error == -1) {
    fprintf(stderr, "Failed to traverse sym2info\n");
    return -1;
  }

  return 0;
}
