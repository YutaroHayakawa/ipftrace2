#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dwarf.h>
#include <elfutils/libdwfl.h>

#include "ipftrace.h"

#define MAX_RECURSE_LEVEL 8

struct dwarf_debuginfo {
  struct ipft_debuginfo base;
  Dwfl *dwfl;
};

// Took from Systemtap
static char *debuginfo_path =
    "+:/usr/lib/debug:/var/cache/abrt-di/usr/lib/debug";

const Dwfl_Callbacks dwfl_callbacks = {
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .debuginfo_path = &debuginfo_path,
    .find_elf = dwfl_linux_kernel_find_elf,
    .section_address = dwfl_linux_kernel_module_section_address};

static void dwfl_perror(const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, dwfl_errmsg(dwfl_errno()));
}

static void dwarf_perror(const char *msg) {
  fprintf(stderr, "%s: %s\n", msg, dwarf_errmsg(dwarf_errno()));
}

static ptrdiff_t find_member_offset(Dwarf_Die *die, int level,
    ptrdiff_t offset, const char *name) {
  int tag;
  ptrdiff_t ret;
  Dwarf_Word uval;
  Dwarf_Attribute *attr, attr_mem;
  Dwarf_Die *type, type_mem, child;

  if (level == MAX_RECURSE_LEVEL) {
    return 0;
  }

  /*
   * Get member type die
   */
  if (dwarf_child(die, &child) != 0) {
    return 0;
  }

  /*
   * Traverse all members recursively
   */
  do {
    /*
     * Skip the sibling other than member (is this possible?)
     */
    if (dwarf_tag(&child) != DW_TAG_member) {
      continue;
    }

    /*
     * Get the member offset from attribute
     */
    attr = dwarf_attr(&child, DW_AT_data_member_location, &attr_mem);
    if (attr != NULL) {
      /*
       * Get the actual offset
       */
      if (dwarf_formudata(attr, &uval) != 0) {
        return -1;
      }
    } else {
      uval = 0;
    }

    /*
     * Get the member type die
     */
    type =
        dwarf_formref_die(dwarf_attr(&child, DW_AT_type, &attr_mem), &type_mem);
    if (type == NULL) {
      return -1;
    }

    tag = dwarf_tag(type);
    switch (tag) {
    case DW_TAG_structure_type:
    case DW_TAG_union_type:
      level++;
      ret = find_member_offset(type, level, offset + uval, name);
      if (ret > 0 || ret == -1) {
        return ret;
      }
      level--;
      break;
    default:
      if (strcmp(dwarf_diename(&child), name) == 0) {
        return offset + uval;
      }
      break;
    }
  } while (dwarf_siblingof(&child, &child) == 0);

  return 0;
}

static int dwarf_scan_func_die(Dwarf_Die *die, void *arg) {
  Dwarf_Die child;
  int i = 0, tag;
  int error;
  struct ipft_syminfo si;
  struct ipft_symsdb *db;

  if (dwarf_child(die, &child) != 0) {
    return DWARF_CB_OK;
  }

  db = (struct ipft_symsdb *)arg;

  do {
    i++;
    tag = dwarf_tag(&child);
    if (tag == DW_TAG_formal_parameter) {
      /*
       * skb_pos should be <= 4 due to the limitation of
       * eBPF + kprobe.
       */
      if (dwarf_diename(&child) != NULL && i <= 4) {
        Dwarf_Attribute attr;
        Dwarf_Die *param_type, param_type_mem;
        Dwarf_Die *ptr_type, ptr_type_mem;

        /*
         * Make sure the function parameter is struct sk_buff *skb
         */

        /*
         * Get the type attribute of the function parameter
         */
        param_type = dwarf_formref_die(dwarf_attr(&child, DW_AT_type, &attr),
                                       &param_type_mem);
        if (param_type == NULL) {
          continue;
        }

        /*
         * Make sure it is a pointer
         */
        tag = dwarf_tag(param_type);
        if (tag != DW_TAG_pointer_type) {
          continue;
        }

        /*
         * Get the original type of the pointer
         */
        ptr_type = dwarf_formref_die(dwarf_attr(param_type, DW_AT_type, &attr),
                                     &ptr_type_mem);
        if (ptr_type == NULL) {
          continue;
        }

        /*
         * Make sure it is a struct
         */
        tag = dwarf_tag(ptr_type);
        if (tag != DW_TAG_structure_type) {
          continue;
        }

        /*
         * Make sure the name of the struct is "sk_buff"
         */
        if (strcmp("sk_buff", dwarf_diename(ptr_type)) != 0) {
          continue;
        }

        /*
         * Put the function information to the symsdb
         */
        si.skb_pos = i;
        error = symsdb_put_sym2info(db, (char *)dwarf_diename(die), &si);
        if (error == -1) {
          fprintf(stderr, "Failed to put sym2info\n");
          return -1;
        }

        break;
      }
    }
  } while (dwarf_siblingof(&child, &child) == 0);

  return DWARF_CB_OK;
}

static int dwarf_debuginfo_fill_sym2info(struct ipft_debuginfo *_dinfo,
                                         struct ipft_symsdb *sdb) {
  ptrdiff_t ret;
  Dwarf_Addr addr;
  Dwarf_Die *cu = NULL;
  struct dwarf_debuginfo *dinfo;

  dinfo = (struct dwarf_debuginfo *)_dinfo;

  while ((cu = dwfl_nextcu(dinfo->dwfl, cu, &addr)) != NULL) {
    ret = dwarf_getfuncs(cu, dwarf_scan_func_die, sdb, 0);
    if (ret == -1) {
      dwarf_perror("dwarf_getfuncs");
      return -1;
    }
  }

  return 0;
}

static bool
is_ctype(int tag)
{
  return tag == DW_TAG_array_type ||
         tag == DW_TAG_enumeration_type ||
         tag == DW_TAG_pointer_type ||
         tag == DW_TAG_structure_type ||
         tag == DW_TAG_typedef ||
         tag == DW_TAG_union_type;
}

static int get_ctype_die(struct dwarf_debuginfo *dinfo,
    const char *name, Dwarf_Die **diep) {
  int tag;
  Dwarf_Addr addr;
  Dwarf_Die *child;
  const char *die_name;
  Dwarf_Die *cu = NULL;

  child = malloc(sizeof(*child));
  if (child == NULL) {
    perror("malloc");
    return -1;
  }

  while ((cu = dwfl_nextcu(dinfo->dwfl, cu, &addr)) != NULL) {
    if (dwarf_child(cu, child) != 0) {
      continue;
    }

    do {
      tag = dwarf_tag(child);
      if (!is_ctype(tag)) {
        continue;
      }

      die_name = dwarf_diename(child);
      if (die_name == NULL) {
        continue;
      }

      if (strcmp(name, dwarf_diename(child)) == 0) {
        *diep = child;
        goto end;
      }
    } while (dwarf_siblingof(child, child) == 0);
  }

  free(child);

end:
  return 0;
}

static int dwarf_sizeof(struct ipft_debuginfo *dinfo,
    const char *type, size_t *sizep) {
  int error, size;
  Dwarf_Die *die;

  error = get_ctype_die((struct dwarf_debuginfo *)dinfo,
      type, &die);
  if (error == -1) {
    fprintf(stderr, "Couldn't find type die\n");
    return -1;
  }

  size = dwarf_bytesize(die);
  if (size == -1) {
    fprintf(stderr, "Couldn't get size\n");
    return -1;
  }

  *sizep = size;

  return 0;
}

static int dwarf_offsetof(struct ipft_debuginfo *dinfo,
    const char *type, const char *member, size_t *offsetp) {
  int tag, error;
  Dwarf_Die *die;
  ptrdiff_t offset;

  error = get_ctype_die((struct dwarf_debuginfo *)dinfo,
      type, &die);
  if (error == -1) {
    fprintf(stderr, "Couldn't find type die\n");
    return -1;
  }

  tag = dwarf_tag(die);
  if (tag != DW_TAG_structure_type &&
      tag != DW_TAG_union_type) {
    fprintf(stderr, "%s is not a struct or union\n", type);
    return -1;
  }

  offset = find_member_offset(die, 0, 0, member);
  if (offset == -1) {
    fprintf(stderr, "Couldn't find member offset\n");
    return -1;
  }

  *offsetp = offset;

  return 0;
}

static void dwarf_debuginfo_destroy(struct ipft_debuginfo *_dinfo) {
  struct dwarf_debuginfo *dinfo;
  dinfo = (struct dwarf_debuginfo *)_dinfo;
  dwfl_end(dinfo->dwfl);
}

int dwarf_debuginfo_create(struct ipft_debuginfo **dinfop) {
  int error;
  Dwfl *dwfl;
  struct dwarf_debuginfo *dinfo;

  dwfl = dwfl_begin(&dwfl_callbacks);
  if (dwfl == NULL) {
    dwfl_perror("dwfl_begin");
    return -1;
  }

  error = dwfl_linux_kernel_report_kernel(dwfl);
  if (error != 0) {
    dwfl_perror("dwfl_linux_kernel_report_kernel");
    goto err;
  }

  error = dwfl_linux_kernel_report_modules(dwfl);
  if (error != 0) {
    dwfl_perror("dwfl_linux_kernel_report_modules");
    goto err;
  }

  dinfo = (struct dwarf_debuginfo *)malloc(sizeof(*dinfo));
  if (dinfo == NULL) {
    perror("malloc");
    goto err;
  }

  dinfo->base.fill_sym2info = dwarf_debuginfo_fill_sym2info;
  dinfo->base.sizeof_fn = dwarf_sizeof;
  dinfo->base.offsetof_fn = dwarf_offsetof;
  dinfo->base.destroy = dwarf_debuginfo_destroy;
  dinfo->dwfl = dwfl;

  *dinfop = (struct ipft_debuginfo *)dinfo;

  return 0;

err:
  dwfl_end(dwfl);
  return -1;
}
