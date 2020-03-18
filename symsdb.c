#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <unistd.h>
#include <dwarf.h>
#include <elfutils/libdwfl.h>

#include "khash.h"

#include "ipftrace.h"

#define MAX_RECURSE_LEVEL 7

#define assert_malloc(_ptr) do { \
  if (_ptr == NULL) { \
    fprintf(stderr, "Cannot allocate memory\n"); \
    exit(EXIT_FAILURE); \
  } \
} while (0)

KHASH_MAP_INIT_STR(sym2info, struct ipft_syminfo *)
KHASH_MAP_INIT_INT64(addr2sym, char *)

struct ipft_symsdb {
  ptrdiff_t mark_offset;
  khash_t(sym2info) *sym2info;
  khash_t(addr2sym) *addr2sym;
};

static ptrdiff_t
get_mark_offset(Dwarf_Die *die, int level, ptrdiff_t offset)
{
  int tag;
  ptrdiff_t ret;
  Dwarf_Word uval;
  Dwarf_Attribute *attr, attr_mem;
  Dwarf_Die *type, type_mem, child;

  if (level == MAX_RECURSE_LEVEL) {
    return -1;
  }

  /*
   * Get member type die
   */
  if (dwarf_child(die, &child) != 0) {
    return -1;
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
    type = dwarf_formref_die(dwarf_attr(&child, DW_AT_type, &attr_mem), &type_mem);
    if (type == NULL) {
      return -1;
    }

    tag = dwarf_tag(type);
    switch(tag) {
      case DW_TAG_structure_type:
      case DW_TAG_union_type:
        level++;
        ret = get_mark_offset(type, level, offset + uval);
        if (ret > 0 || ret == -1) {
          return ret;
        }
        level--;
        break;
      default:
        if (strcmp(dwarf_diename(&child), "mark") == 0) {
          return offset + uval;
        }
        break;
    }
  } while (dwarf_siblingof(&child, &child) == 0);

  return 0;
}

static int
dwarf_scan_func_die(Dwarf_Die *die, void *arg)
{
  char *sym;
  int level = 0;
  khint_t iter;
  Dwarf_Die child;
  int i = 0, ret, tag;
  ptrdiff_t offset = 0;
  struct ipft_symsdb *db;
  struct ipft_syminfo *si;

  if (dwarf_child(die, &child) != 0) {
    return DWARF_CB_OK;
  }

  db = (struct ipft_symsdb *)arg;

  do {
    i++;
    tag = dwarf_tag(&child);
    if (tag == DW_TAG_formal_parameter) {
      /*
       * FIXME: This is a stupid way, but works well thanks to
       * well organized kernel naming convention. This allows
       * us to write syms collection in single pass.
       */
      if (dwarf_diename(&child) != NULL &&
          strcmp(dwarf_diename(&child), "skb") == 0 &&
          i <= 4) {
        Dwarf_Attribute attr;
        Dwarf_Die *param_type, param_type_mem;
        Dwarf_Die *ptr_type, ptr_type_mem;

        /*
         * Make sure the function parameter is struct sk_buff *skb
         */

        /*
         * Get the type attribute of the function parameter
         */
        param_type = dwarf_formref_die(
            dwarf_attr(&child, DW_AT_type, &attr), &param_type_mem);
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
        ptr_type = dwarf_formref_die(
            dwarf_attr(param_type, DW_AT_type, &attr), &ptr_type_mem);
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
         * If we don't know the offset of the mark,
         * scan all over struct and get it
         */
        if (db->mark_offset == -1) {
          db->mark_offset = get_mark_offset(ptr_type, level, offset);
          if (db->mark_offset == -1) {
            fprintf(stderr, "Failed to get mark offset. Unexpected DWARF format.\n");
            return -1;
          } else if (db->mark_offset > 0) {
            printf("mark_offset: %lx\n", db->mark_offset);
          }
        }

        sym = strdup(dwarf_diename(die));
        assert_malloc(sym);

        iter = kh_put(sym2info, db->sym2info, sym, &ret);
        if (ret != 0) {
          si = malloc(sizeof(*si));
          assert_malloc(si);
          si->skb_pos = i;
          kh_value(db->sym2info, iter) = si;
        } else {
          free(sym);
        }

        break;
      }
    }
  } while(dwarf_siblingof(&child, &child) == 0);

  return DWARF_CB_OK;
}

static int
dwarf_collect_syms(struct ipft_symsdb *db)
{
  int error;
  Dwfl *dwfl;
  ptrdiff_t ret;
  Dwarf_Addr addr;
  Dwarf_Die *cu = NULL;
  char *debuginfo_path = NULL;

  const Dwfl_Callbacks dwfl_callbacks = {
    .find_debuginfo = dwfl_standard_find_debuginfo,
    .debuginfo_path = &debuginfo_path,
    .find_elf = dwfl_linux_kernel_find_elf,
    .section_address = dwfl_linux_kernel_module_section_address
  };

  dwfl = dwfl_begin(&dwfl_callbacks);
  if (dwfl == NULL) {
    fprintf(stderr, "dwfl_begin: %s\n", dwfl_errmsg(dwfl_errno()));
    goto err;
  }

  error = dwfl_linux_kernel_report_kernel(dwfl);
  if (error != 0) {
    fprintf(stderr, "dwfl_linux_kernel_report_kernel: %s\n", dwfl_errmsg(dwfl_errno()));
    goto err;
  }

  error = dwfl_linux_kernel_report_modules(dwfl);
  if (error != 0) {
    fprintf(stderr, "dwfl_linux_kernel_report_modules: %s\n", dwfl_errmsg(dwfl_errno()));
    goto err;
  }

  while ((cu = dwfl_nextcu(dwfl, cu, &addr)) != NULL) {
    ret = dwarf_getfuncs(cu, dwarf_scan_func_die, db, 0);
    if (ret == -1) {
      fprintf(stderr, "dwarf_getfuncs: %s\n", dwfl_errmsg(dwfl_errno()));
      goto err;
    }
  }

  dwfl_end(dwfl);
  return 0;

err:
  return -1;
}

static int
btf_collect_syms(struct ipft_symsdb *db)
{
  fprintf(stderr, "BTF format is not supported currently. Sorry.\n");
  return 0;
}

static int
sym2info_fill(struct ipft_symsdb *db, struct ipft_symsdb_opt *opt)
{
  int error;

  if (strcmp(opt->format, "dwarf") == 0) {
    error = dwarf_collect_syms(db);
  } else if (strcmp(opt->format, "btf") == 0) {
    error = btf_collect_syms(db);
  } else {
    fprintf(stderr, "Unknown format: %s\n", opt->format);
    error = -1;
  }

  return error;
}

/*
 * Took from bcc (https://github.com/iovisor/bcc)
 */
#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
const unsigned long long kernel_addr_space = 0x00ffffffffffffff;
#else
const unsigned long long kernel_addr_spacee = 0x0;
#endif

static int
addr2sym_fill(struct ipft_symsdb *db)
{
  FILE *f;
  khint_t iter;
  uint64_t addr;
  int error, ret;
  char line[2048];
  khash_t(sym2info) *sym2info;
  khash_t(addr2sym) *addr2sym;
  char *name, *symname, *endsym;

  sym2info = db->sym2info;
  addr2sym = db->addr2sym;

  f = fopen("/proc/kallsyms", "r");
  if (f == NULL) {
    error = errno;
    fprintf(stderr, "Failed to open /proc/kallsyms: %s\n",
        strerror(error));
    return error;
  }

  if (geteuid() != 0) {
    return EPERM;
  }

  while (fgets(line, sizeof(line), f)) {
    addr = strtoull(line, &symname, 16);
    if (addr == 0 || addr == ULLONG_MAX) {
      continue;
    }

    if (addr < kernel_addr_space) {
      continue;
    }

    symname++;

    // Ignore data symbols
    if (*symname == 'b' || *symname == 'B' || *symname == 'd' ||
        *symname == 'D' || *symname == 'r' || *symname =='R') {
      continue;
    }

    symname += 2;

    endsym = symname;
    while (*endsym && !isspace(*endsym)) {
      endsym++;
    }

    *endsym = '\0';

    name = strndup(symname, endsym - symname);
    assert_malloc(name);

    iter = kh_get(sym2info, sym2info, name);
    if (iter != kh_end(sym2info)) {
      iter = kh_put(addr2sym, addr2sym, addr, &ret);
      if (ret != 0) {
        kh_value(addr2sym, iter) = name;
      }
    } else {
      free(name);
    }
  }

  fclose(f);

  return 0;
}

ptrdiff_t
ipft_symsdb_get_mark_offset(struct ipft_symsdb *_db)
{
  return _db->mark_offset;
}

char *
ipft_symsdb_addr2sym(struct ipft_symsdb *_db, uint64_t addr)
{
  khint_t iter;
  khash_t(addr2sym) *db = (khash_t(addr2sym) *)_db;

  iter = kh_get(addr2sym, db, addr);
  if (iter == kh_end(db)) {
    return NULL;
  }

  return kh_value(db, iter);
}

struct ipft_syminfo *
ipft_symsdb_sym2info(struct ipft_symsdb *_db, char *sym)
{
  khint_t iter;
  khash_t(sym2info) *db = (khash_t(sym2info) *)_db;

  iter = kh_get(sym2info, db, sym);
  if (iter == kh_end(db)) {
    return NULL;
  }

  return kh_value(db, iter);
}

int
ipft_symsdb_foreach_syms(struct ipft_symsdb *db,
    int (*cb)(const char *sym, struct ipft_syminfo *si, void *arg),
    void *arg)
{
  const char *sym;
  struct ipft_syminfo *si;
  kh_foreach(db->sym2info, sym, si,
    if (cb(sym, si, arg) != 0) {
      return -1;
    }
  );
  return 0;
}

int
ipft_symsdb_create(struct ipft_symsdb **dbp, struct ipft_symsdb_opt *opt)
{
  int error = 0;
  struct ipft_symsdb *db;

  db = (struct ipft_symsdb *)malloc(sizeof(*db));
  assert_malloc(db);

  db->mark_offset = -1;

  db->sym2info = kh_init(sym2info);
  assert_malloc(db);

  db->addr2sym = kh_init(addr2sym);
  assert_malloc(db);

  error = sym2info_fill(db, opt);
  if (error != 0) {
    return error;
  }

  error = addr2sym_fill(db);
  if (error != 0) {
    return error;
  }

  *dbp = db;

  return error;
}

/*
int
main(int argc, char **argv)
{
  int error;
  struct ipft_symsdb *db;
  struct ipft_symsdb_opt opt = {
    .format = "dwarf",
  };

  error = ipft_symsdb_create(&db, &opt);
  if (error != 0) {
    fprintf(stderr, "ipft_symsdb_create: %s\n", strerror(error));
    return EXIT_FAILURE;
  }

  char *sym;
  struct ipft_syminfo *si;
  kh_foreach(db->sym2info, sym, si,
    if (si->skb_pos != 0) {
      printf("%s\t%d\n", sym, si->skb_pos);
    }
  );

  return EXIT_SUCCESS;
}
*/
