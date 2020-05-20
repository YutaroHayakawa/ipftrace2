#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <linux/bpf.h>

#include "ipftrace.h"

#define __unused __attribute__((unused))

static int
debuginfo_create(struct ipft_debuginfo **dinfop, const char *type)
{
  int error;

  if (strcmp(type, "dwarf") == 0) {
    error = dwarf_debuginfo_create(dinfop);
  } else if (strcmp(type, "btf") == 0) {
    error = btf_debuginfo_create(dinfop);
  } else {
    /* Impossible. Already checked. */
    assert(false);
  }

  return error;
}

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

  error = debuginfo_create(&dinfo, opt->debug_info_type);
  if (error == -1) {
    fprintf(stderr, "Error in initializing debuginfo\n");
    goto err0;
  }

  error = debuginfo_fill_sym2info(dinfo, sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to fill sym2info\n");
    goto err1;
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

  error = script_create(&script, dinfo, opt->script_path);
  if (error == -1) {
    fprintf(stderr, "Failed to create script\n");
    goto err0;
  }

  error = script_exec_emit(script, &mod, &mod_cnt);
  if (error == -1) {
    fprintf(stderr, "Execution of emit function failed\n");
    goto err1;
  }

  error = debuginfo_offsetof(dinfo, "sk_buff", "mark", &offset);
  if (error == -1) {
    fprintf(stderr, "Cannot get offset of the mark\n");
    goto err2;
  }

  error = bpf_prog_load(&prog, 0xdeadbeef, offset, mod, mod_cnt);
  if (error == -1) {
    fprintf(stderr, "Failed to load prog\n");
    goto err2;
  }

  bpf_prog_unload(prog);

err2:
  free(mod);
err1:
  script_destroy(script);
err0:
  debuginfo_destroy(dinfo);
  return error;
}
