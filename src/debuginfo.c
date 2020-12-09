/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipftrace.h"

int
debuginfo_create(struct ipft_debuginfo **dinfop)
{
  return btf_debuginfo_create(dinfop);
}

int
debuginfo_fill_sym2info(struct ipft_debuginfo *dinfo, struct ipft_symsdb *sdb)
{
  return dinfo->fill_sym2info(dinfo, sdb);
}

int
debuginfo_sizeof(struct ipft_debuginfo *dinfo, const char *type, size_t *sizep)
{
  return dinfo->sizeof_fn(dinfo, type, sizep);
}

int
debuginfo_offsetof(struct ipft_debuginfo *dinfo, const char *type,
                   const char *member, size_t *offsetp)
{
  return dinfo->offsetof_fn(dinfo, type, member, offsetp);
}

int
debuginfo_typeof(struct ipft_debuginfo *dinfo, const char *type,
                 const char *member, char **namep)
{
  return dinfo->typeof_fn(dinfo, type, member, namep);
}
