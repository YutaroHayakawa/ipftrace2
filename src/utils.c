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
list_functions(struct ipft_tracer_opt *opt)
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
    goto err1;
  }

err1:
  debuginfo_destroy(dinfo);
err0:
  symsdb_destroy(sdb);
  return error;
}

int
test_bpf_prog(struct ipft_tracer_opt *opt)
{
  int error;
  size_t offset;
  uint32_t mod_cnt;
  struct bpf_insn *mod;
  struct ipft_script *script;
  struct ipft_bpf_prog *prog;
  struct ipft_debuginfo *dinfo;

  error = debuginfo_create(&dinfo, opt->debug_info_type);
  if (error == -1) {
    fprintf(stderr, "Failed to create debug info\n");
    return -1;
  }

  return 0;
}
