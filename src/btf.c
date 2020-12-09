/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/btf.h>

#include "ipftrace.h"

struct btf_debuginfo {
  struct ipft_debuginfo base;
  struct btf_header *btf;
  struct btf_type **types;
  size_t ntypes;
};

static ssize_t
btf_type_size(struct btf_type *t)
{
  ssize_t base = sizeof(*t);
  uint16_t vlen = BTF_INFO_VLEN(t->info);

  switch (BTF_INFO_KIND(t->info)) {
  case BTF_KIND_FWD:
  case BTF_KIND_CONST:
  case BTF_KIND_VOLATILE:
  case BTF_KIND_RESTRICT:
  case BTF_KIND_PTR:
  case BTF_KIND_TYPEDEF:
  case BTF_KIND_FUNC:
    return base;
  case BTF_KIND_INT:
    return base + sizeof(uint32_t);
  case BTF_KIND_ENUM:
    return base + vlen * sizeof(struct btf_enum);
  case BTF_KIND_ARRAY:
    return base + sizeof(struct btf_array);
  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION:
    return base + vlen * sizeof(struct btf_member);
  case BTF_KIND_FUNC_PROTO:
    return base + vlen * sizeof(struct btf_param);
  case BTF_KIND_VAR:
    return base + sizeof(struct btf_var);
  case BTF_KIND_DATASEC:
    return base + vlen * sizeof(struct btf_var_secinfo);
  default:
    fprintf(stderr, "Unsupported BTF_KIND:%u\n", BTF_INFO_KIND(t->info));
    return -1;
  }
}

static int
resolve_type(struct btf_debuginfo *dinfo, struct btf_type *t, int level,
             struct btf_type **tp)
{
  struct btf_type *orig_type;

  if (level == MAX_RECURSE_LEVEL) {
    fprintf(stderr, "Max recurse level reached\n");
    return -1;
  }

  orig_type = dinfo->types[t->type];

  switch (BTF_INFO_KIND(orig_type->info)) {
  case BTF_KIND_INT:
  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION:
  case BTF_KIND_ENUM:
  case BTF_KIND_DATASEC:
  case BTF_KIND_PTR:
  case BTF_KIND_ARRAY:
    *tp = orig_type;
    return 0;
  }

  return resolve_type(dinfo, orig_type, level + 1, tp);
}

static int
parse_types(struct btf_debuginfo *dinfo)
{
  ssize_t tsize;
  uint8_t *cur, *end;
  size_t idx, ntypes;
  struct btf_header *btf;
  struct btf_type *type, **types;

  btf = dinfo->btf;

  ntypes = btf->type_len / sizeof(**types) + 2;

  types = calloc(sizeof(*types), ntypes);
  if (types == NULL) {
    perror("calloc");
    return -1;
  }

  idx = 1;
  cur = (uint8_t *)(btf + 1) + btf->type_off;
  end = (uint8_t *)(btf + 1) + btf->str_off;
  while (cur < end) {
    type = (struct btf_type *)cur;
    tsize = btf_type_size(type);
    if (tsize == -1) {
      fprintf(stderr, "Failed to get type size\n");
      return -1;
    }
    cur += tsize;
    types[idx] = type;
    idx++;
  }

  dinfo->types = types;
  dinfo->ntypes = idx;

  return 0;
}

static int
fill_sym2info(struct btf_debuginfo *dinfo, struct ipft_symsdb *sdb)
{
  int error;
  struct btf_header *btf;
  struct ipft_syminfo sinfo;
  char *str_sec, *st_name, *func_name;
  struct btf_param *param_base, *param;
  struct btf_type **types, *ptr, *st, *func, *func_proto;

  btf = dinfo->btf;
  str_sec = (char *)(btf + 1) + btf->str_off;

  types = dinfo->types;

  for (size_t i = 1; i < dinfo->ntypes; i++) {
    func = types[i];
    if (BTF_INFO_KIND(func->info) == BTF_KIND_FUNC) {
      func_name = str_sec + func->name_off;
      func_proto = types[func->type];
      param_base = (struct btf_param *)(func_proto + 1);
      for (uint16_t i = 0;
           i < BTF_INFO_VLEN(func_proto->info) && i < MAX_SKB_POS - 1; i++) {
        param = param_base + i;

        /*
         * Variable length argument
         */
        if (param->type == 0) {
          break;
        }

        ptr = types[param->type];
        if (BTF_INFO_KIND(ptr->info) == BTF_KIND_PTR) {
          st = types[ptr->type];
          /* ptr->type == 0 means void * */
          if (ptr->type != 0 && BTF_INFO_KIND(st->info) == BTF_KIND_STRUCT) {
            st_name = str_sec + st->name_off;
            if (strcmp(st_name, "sk_buff") == 0) {
              sinfo.skb_pos = i + 1;

              error = symsdb_put_sym2info(sdb, func_name, &sinfo);
              if (error == -1) {
                fprintf(stderr, "symsdb_put_sym2info failed\n");
                return -1;
              }

              break;
            }
          }
        }
      }
    }
  }

  return 0;
}

static int
get_type_from_name(struct btf_debuginfo *dinfo, const char *name,
                   struct btf_type **tp)
{
  char *str_sec;
  struct btf_type *t;

  str_sec = (char *)(dinfo->btf + 1) + dinfo->btf->str_off;

  for (size_t i = 1; i < dinfo->ntypes; i++) {
    t = dinfo->types[i];
    if (strcmp(name, str_sec + t->name_off) == 0) {
      *tp = t;
      return 0;
    }
  }

  return -1;
}

static int
get_member_offset(struct btf_debuginfo *dinfo, int level, struct btf_type *t,
                  const char *member, size_t *offsetp)
{
  int error;
  struct btf_type *mt;
  char *name, *str_sec;
  struct btf_member *m, *base;

  str_sec = (char *)(dinfo->btf + 1) + dinfo->btf->str_off;

  if (level == MAX_RECURSE_LEVEL) {
    fprintf(stderr, "Max recurse level reached\n");
    return -1;
  }

  if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT &&
      BTF_INFO_KIND(t->info) != BTF_KIND_UNION) {
    name = str_sec + t->name_off;
    fprintf(stderr, "Type %s is not struct or union\n",
            name[0] == '\0' ? "(noname)" : name);
    return -1;
  }

  base = (struct btf_member *)(t + 1);

  for (uint32_t i = 0; i < BTF_INFO_VLEN(t->info); i++) {
    m = base + i;

    if (strcmp(str_sec + m->name_off, member) == 0) {
      if (!BTF_INFO_KFLAG(t->info)) {
        *offsetp += m->offset / 8;
      } else {
        /*
         * Make the behavior for bitfields compatible with DWARF
         * until we support it.
         */
        *offsetp += BTF_MEMBER_BIT_OFFSET(m->offset) / 8;
      }
      return 0;
    }

    mt = dinfo->types[m->type];

    switch (BTF_INFO_KIND(mt->info)) {
    case BTF_KIND_INT:
    case BTF_KIND_PTR:
    case BTF_KIND_ARRAY:
    case BTF_KIND_ENUM:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
      break;
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
      *offsetp += m->offset / 8;
      error = get_member_offset(dinfo, level + 1, mt, member, offsetp);
      if (error == 1) {
        *offsetp -= m->offset / 8;
      } else if (error == -1) {
        fprintf(stderr, "get_member_offset failed\n");
        return -1;
      } else {
        return 0;
      }
      break;
    case BTF_KIND_FWD:
    case BTF_KIND_FUNC:
    case BTF_KIND_FUNC_PROTO:
    case BTF_KIND_VAR:
    case BTF_KIND_DATASEC:
      fprintf(stderr, "Unexpected BTF kind inside the struct/union %d",
              BTF_INFO_KIND(t->info));
      return -1;
    default:
      fprintf(stderr, "Unsupported BTF kind\n");
      return -1;
    }
  }

  return 1;
}

static int
get_member_type(struct btf_debuginfo *dinfo, int level, struct btf_type *t,
                const char *member, char **namep)
{
  int error;
  struct btf_type *mt;
  char *name, *str_sec;
  struct btf_member *m, *base;

  str_sec = (char *)(dinfo->btf + 1) + dinfo->btf->str_off;

  if (level == MAX_RECURSE_LEVEL) {
    fprintf(stderr, "Max recurse level reached\n");
    return -1;
  }

  if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT &&
      BTF_INFO_KIND(t->info) != BTF_KIND_UNION) {
    name = str_sec + t->name_off;
    fprintf(stderr, "Type %s is not struct or union\n",
            name[0] == '\0' ? "(noname)" : name);
    return -1;
  }

  base = (struct btf_member *)(t + 1);

  for (uint32_t i = 0; i < BTF_INFO_VLEN(t->info); i++) {
    m = base + i;
    mt = dinfo->types[m->type];

    if (strcmp(str_sec + m->name_off, member) == 0) {
      /*
       * FIXME: Need to do extra strdup to make the behavior
       * compatible with DWARF
       */
      if (BTF_INFO_KIND(mt->info) == BTF_KIND_PTR) {
        *namep = strdup("uintptr_t");
      } else {
        *namep = strdup(str_sec + mt->name_off);
      }
      return 0;
    }

    switch (BTF_INFO_KIND(mt->info)) {
    case BTF_KIND_INT:
    case BTF_KIND_PTR:
    case BTF_KIND_ARRAY:
    case BTF_KIND_ENUM:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
      break;
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
      error = get_member_type(dinfo, level + 1, mt, member, namep);
      if (error == -1) {
        fprintf(stderr, "get_member_offset failed\n");
        return -1;
      } else if (error == 0) {
        return 0;
      }
      break;
    case BTF_KIND_FWD:
    case BTF_KIND_FUNC:
    case BTF_KIND_FUNC_PROTO:
    case BTF_KIND_VAR:
    case BTF_KIND_DATASEC:
      fprintf(stderr, "Unexpected BTF kind inside the struct/union %d",
              BTF_INFO_KIND(t->info));
      return -1;
    default:
      fprintf(stderr, "Unsupported BTF kind\n");
      return -1;
    }
  }

  return 1;
}

static int
get_size(struct btf_debuginfo *dinfo, struct btf_type *t, size_t *sizep)
{
  int error;
  size_t size;
  struct btf_type *orig;

  switch (BTF_INFO_KIND(t->info)) {
  case BTF_KIND_INT:
    size = t->size;
    break;
  case BTF_KIND_PTR:
    size = sizeof(uintptr_t);
    break;
  case BTF_KIND_ARRAY:
    fprintf(stderr, "Array is not supported yet, sorry\n");
    return -1;
  case BTF_KIND_STRUCT:
  case BTF_KIND_UNION:
    size = t->size;
    break;
  case BTF_KIND_ENUM:
    size = 4;
    break;
  case BTF_KIND_FWD:
    fprintf(stderr, "Cannot get the size of the forward declaration\n");
    return -1;
  case BTF_KIND_TYPEDEF:
  case BTF_KIND_VOLATILE:
  case BTF_KIND_CONST:
  case BTF_KIND_RESTRICT:
    error = resolve_type(dinfo, t, 0, &orig);
    if (error == -1) {
      fprintf(stderr, "Failed to resolve type\n");
      return -1;
    }

    error = get_size(dinfo, orig, &size);
    if (error == -1) {
      fprintf(stderr, "Failed to get size of the original size\n");
      return -1;
    }

    break;
  case BTF_KIND_FUNC:
    fprintf(stderr, "Cannot get sizeof the func\n");
    return -1;
  case BTF_KIND_FUNC_PROTO:
    fprintf(stderr, "Cannot get sizeof the func proto\n");
    return -1;
  case BTF_KIND_VAR:
    fprintf(stderr, "Cannot get sizeof the var\n");
    return -1;
  case BTF_KIND_DATASEC:
    fprintf(stderr, "Cannot get sizeof the datasec\n");
    return -1;
  default:
    fprintf(stderr, "Unsupported BTF kind\n");
    return -1;
  }

  *sizep = size;

  return 0;
}

static int
btf_sizeof(struct ipft_debuginfo *_dinfo, const char *type, size_t *sizep)
{
  int error;
  size_t size;
  struct btf_type *t;
  struct btf_debuginfo *dinfo = (struct btf_debuginfo *)_dinfo;

  error = get_type_from_name(dinfo, type, &t);
  if (error == -1) {
    return -1;
  }

  error = get_size(dinfo, t, &size);
  if (error == -1) {
    return -1;
  }

  *sizep = size;

  return 0;
}

static int
btf_offsetof(struct ipft_debuginfo *_dinfo, const char *type,
             const char *member, size_t *offsetp)
{
  int error;
  struct btf_type *t;
  struct btf_debuginfo *dinfo = (struct btf_debuginfo *)_dinfo;

  error = get_type_from_name(dinfo, type, &t);
  if (error == -1) {
    return -1;
  }

  if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT &&
      BTF_INFO_KIND(t->info) != BTF_KIND_UNION) {
    fprintf(stderr, "Type %s is not struct or union\n", type);
    return -1;
  }

  *offsetp = 0;

  error = get_member_offset(dinfo, 0, t, member, offsetp);
  if (error != 0) {
    fprintf(stderr, "Failed to get member offset\n");
    return -1;
  }

  return 0;
}

static int
btf_typeof(struct ipft_debuginfo *_dinfo, const char *type, const char *member,
           char **namep)
{
  int error;
  struct btf_type *t;
  struct btf_debuginfo *dinfo = (struct btf_debuginfo *)_dinfo;

  error = get_type_from_name(dinfo, type, &t);
  if (error == -1) {
    return -1;
  }

  if (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT &&
      BTF_INFO_KIND(t->info) != BTF_KIND_UNION) {
    fprintf(stderr, "Type %s is not struct or union\n", type);
    return -1;
  }

  error = get_member_type(dinfo, 0, t, member, namep);
  if (error != 0) {
    fprintf(stderr, "Failed to get member type\n");
    return -1;
  }

  return 0;
}

static int
read_btf_file(const char *path, struct btf_header **btfp)
{
  FILE *f;
  size_t rsize;
  int error = 0;
  uint8_t *data;
  struct stat st;

  error = stat(path, &st);
  if (error == -1) {
    perror("fstat");
    return -1;
  }

  data = malloc(st.st_size);
  if (data == NULL) {
    perror("malloc");
    return -1;
  }

  f = fopen(path, "r");
  if (f == NULL) {
    perror("fopen");
    goto err0;
  }

  rsize = fread(data, 1, st.st_size, f);
  fclose(f);
  if (rsize < (size_t)st.st_size) {
    fprintf(stderr, "Failed to read entire BTF\n");
    goto err1;
  }

  *btfp = (struct btf_header *)data;

  return 0;

err1:
  fclose(f);
err0:
  free(data);
  return -1;
}

static int
btf_debuginfo_fill_sym2info(struct ipft_debuginfo *_dinfo,
                            struct ipft_symsdb *sdb)
{
  return fill_sym2info((struct btf_debuginfo *)_dinfo, sdb);
}

int
btf_debuginfo_create(struct ipft_debuginfo **dinfop)
{
  int error = 0;
  struct btf_debuginfo *dinfo;

  dinfo = malloc(sizeof(*dinfo));
  if (dinfo == NULL) {
    perror("malloc");
    return -1;
  }

  error = read_btf_file("/sys/kernel/btf/vmlinux", &dinfo->btf);
  if (error == -1) {
    fprintf(stderr, "read_btf_file failed\n");
    goto err0;
  }

  error = parse_types(dinfo);
  if (error == -1) {
    fprintf(stderr, "parse_types\n");
    return -1;
  }

  dinfo->base.fill_sym2info = btf_debuginfo_fill_sym2info;
  dinfo->base.sizeof_fn = btf_sizeof;
  dinfo->base.offsetof_fn = btf_offsetof;
  dinfo->base.typeof_fn = btf_typeof;

  *dinfop = (struct ipft_debuginfo *)dinfo;

  return 0;
}
