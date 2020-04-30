#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ipftrace.h"

int debuginfo_fill_sym2info(struct ipft_debuginfo *dinfo,
                            struct ipft_symsdb *sdb) {
  return dinfo->fill_sym2info(dinfo, sdb);
}

int debuginfo_sizeof(struct ipft_debuginfo *dinfo,
    const char *type, size_t *sizep) {
  return dinfo->sizeof_fn(dinfo, type, sizep);
}

int debuginfo_offsetof(struct ipft_debuginfo *dinfo,
    const char *type, const char *member, size_t *offsetp) {
  return dinfo->offsetof_fn(dinfo, type, member, offsetp);
}

void debuginfo_destroy(struct ipft_debuginfo *dinfo) {
  dinfo->destroy(dinfo);
  free(dinfo);
}
