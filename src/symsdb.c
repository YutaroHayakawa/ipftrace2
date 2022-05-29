#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <errno.h>
#include <fts.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "ipft.h"
#include "khash.h"
#include "kvec.h"

KHASH_MAP_INIT_STR(sym2info, struct ipft_syminfo *)
KHASH_MAP_INIT_INT64(addr2sym, char *)
KHASH_MAP_INIT_STR(availfuncs, int)

struct ipft_symsdb {
  struct ipft_symsdb_opt *opt;
  khash_t(sym2info) * sym2info;
  khash_t(addr2sym) * addr2sym;
  khash_t(availfuncs) * availfuncs;
  kvec_t(const char *) * pos2syms;
};

static void
pos2syms_append(struct ipft_symsdb *sdb, int pos, const char *sym)
{
  kv_push(const char *, sdb->pos2syms[pos], sym);
}

const char *
symsdb_pos2syms_get(struct ipft_symsdb *sdb, int pos, int idx)
{
  return kv_A(sdb->pos2syms[pos], idx);
}

const char **
symsdb_pos2syms_get_array(struct ipft_symsdb *sdb, int pos)
{
  return sdb->pos2syms[pos].a;
}

int
symsdb_get_pos2syms_total(struct ipft_symsdb *sdb, int pos)
{
  return kv_size(sdb->pos2syms[pos]);
}

size_t
symsdb_get_sym2info_total(struct ipft_symsdb *sdb)
{
  return kh_size(sdb->sym2info);
}

static int
put_sym2info(struct ipft_symsdb *sdb, const char *name,
             struct ipft_syminfo *sinfo)
{
  char *k;
  khint_t iter;
  int missing;
  struct ipft_syminfo *v;

  k = strdup(name);
  if (k == NULL) {
    return -1;
  }

  v = (struct ipft_syminfo *)malloc(sizeof(*v));
  if (v == NULL) {
    return -1;
  }

  memcpy(v, sinfo, sizeof(*v));

  iter = kh_put(sym2info, sdb->sym2info, k, &missing);
  if (!missing) {
    /* Already exists */
    return -2;
  }

  kh_value(sdb->sym2info, iter) = v;

  return 0;
}

int
symsdb_get_sym2info(struct ipft_symsdb *sdb, const char *name,
                    struct ipft_syminfo **sinfop)
{
  khint_t iter;
  khash_t(sym2info) * db;

  db = ((struct ipft_symsdb *)sdb)->sym2info;

  iter = kh_get(sym2info, db, name);
  if (iter == kh_end(db)) {
    return -1;
  }

  *sinfop = kh_value(db, iter);

  return 0;
}

int
symsdb_sym2info_foreach(struct ipft_symsdb *sdb,
                        int (*cb)(const char *, struct ipft_syminfo *, void *),
                        void *arg)
{
  int error;
  const char *k;
  struct ipft_syminfo *v;

  kh_foreach(
      sdb->sym2info, k, v, error = cb(k, v, arg);
      if (error == -1) { return -1; })

      return 0;
}

static int
put_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char *sym)
{
  char *v;
  int missing;
  khint_t iter;
  khash_t(addr2sym) * db;

  v = strdup(sym);
  if (v == NULL) {
    return -1;
  }

  db = ((struct ipft_symsdb *)sdb)->addr2sym;

  iter = kh_put(addr2sym, db, addr, &missing);
  if (!missing) {
    return -1;
  }

  kh_value(db, iter) = v;

  return 0;
}

int
symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp)
{
  khint_t iter;
  khash_t(addr2sym) * db;

  db = ((struct ipft_symsdb *)sdb)->addr2sym;

  iter = kh_get(addr2sym, db, addr);
  if (iter == kh_end(db)) {
    fprintf(stderr, "Failed to resolve func addr: %lu\n", addr);
    *symp = "(unknown)";
    return 0;
  }

  *symp = kh_value(db, iter);

  return 0;
}

static int
put_availfuncs(struct ipft_symsdb *sdb, char *sym)
{
  char *k;
  int missing;
  __unused khint_t iter;

  k = strdup(sym);
  if (k == NULL) {
    return -1;
  }

  iter = kh_put(availfuncs, sdb->availfuncs, k, &missing);
  if (missing == -1) {
    fprintf(stderr, "kh_put failed\n");
    return -1;
  } else if (!missing) {
    free(k);
  }

  return 0;
}

static bool
func_is_available(struct ipft_symsdb *sdb, const char *sym)
{
  khint_t iter;

  iter = kh_get(availfuncs, sdb->availfuncs, sym);
  if (iter == kh_end(sdb->availfuncs)) {
    return false;
  }

  return true;
}

static int
fill_availfuncs(struct ipft_symsdb *sdb)
{
  FILE *f;
  int error;
  ssize_t nread;
  size_t len = 0;
  char *line = NULL;

  f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
  if (f == NULL) {
    perror("fopen");
    return -1;
  }

  while ((nread = getline(&line, &len, f)) != -1) {
    char sym[129] = {0};
    char *cur = line;
    while (cur - line != 128) {
      sym[cur - line] = *cur;
      cur++;
      if (*cur == '\n' || *cur == ' ') {
        error = put_availfuncs(sdb, sym);
        if (error == -1) {
          fprintf(stderr, "put_availfuncs failed\n");
          return -1;
        }
        break;
      }
    }
  }

  free(line);
  fclose(f);

  return 0;
}

/*
 * Took from bcc (https://github.com/iovisor/bcc)
 */
#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
const unsigned long long kernel_addr_space = 0x00ffffffffffffff;
#else
const unsigned long long kernel_addr_space = 0x0;
#endif

/*
 * Record the mapping of kernel functions and their addresses
 */
static int
fill_addr2sym(struct ipft_symsdb *sdb)
{
  FILE *f;
  int error;
  uint64_t addr;
  char line[2048];
  char *symname, *endsym;
  struct ipft_syminfo *si;

  f = fopen("/proc/kallsyms", "r");
  if (f == NULL) {
    perror("fopen");
    return -1;
  }

  if (geteuid() != 0) {
    fprintf(
        stderr,
        "Non-root users cannot read address info. Please execute with root.\n");
    return -1;
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
        *symname == 'D' || *symname == 'r' || *symname == 'R') {
      continue;
    }

    symname += 2;
    endsym = symname;
    while (*endsym && !isspace(*endsym)) {
      endsym++;
    }

    *endsym = '\0';

    /*
     * Only add the symbols which are used
     */
    error = symsdb_get_sym2info(sdb, symname, &si);
    if (error == -1) {
      continue;
    }

    /*
     * This shouldn't fail
     */
    error = put_addr2sym(sdb, addr, symname);
    if (error == -1) {
      fprintf(stderr, "put_addr2sym failed\n");
      return -1;
    }
  }

  fclose(f);

  return 0;
}

static int
btf_fill_sym2info(struct ipft_symsdb *sdb, struct btf *btf, bool is_vmlinux_btf)
{
  int error, btf_fd = 0;
  struct ipft_syminfo sinfo;
  const struct btf_param *params;
  const char *func_name, *st_name;
  const struct btf_type *t, *func_proto;

  for (uint32_t id = 0; (t = btf__type_by_id(btf, id)); id++) {
    if (!btf_is_func(t)) {
      continue;
    }

    func_name = btf__str_by_offset(btf, t->name_off);

    /*
     * Only add the symbols which are available for tracing
     */
    if (!func_is_available(sdb, func_name)) {
      continue;
    }

    func_proto = btf__type_by_id(btf, t->type);
    params = btf_params(func_proto);

    /*
     * We need this check because frace program cannot be attached to
     * the function takes more than max_args arguments.
     */
    if (btf_vlen(func_proto) > sdb->opt->max_args) {
      continue;
    }

    bool abort = false;
    for (uint16_t i = 0; i < btf_vlen(func_proto); i++) {
      t = btf__type_by_id(btf, params[i].type);

      /*
       * Strip modifier and typedef to get true data type
       */
      while (btf_is_mod(t) || btf_is_typedef(t)) {
        t = btf__type_by_id(btf, t->type);
      }

      // Last argument is a variable length, ftrace cannot support it.
      if (params[i].type == 0 && params[i].name_off == 0) {
        abort = true;
        break;
      }

      /*
       * Depending on the version, the kernel doesn't allow us to
       * attach fentry/fexit program to functions takes struct/union
       * (not pointer to struct/union) as argument.
       */
      if (btf_is_struct(t) || btf_is_union(t)) {
        abort = true;
        break;
      }
    }

    if (abort) {
      continue;
    }

    /*
     * Find the type "struct sk_buff *" from function arguments
     * and record its position.
     */
    for (uint16_t i = 0; i < btf_vlen(func_proto) && i < sdb->opt->max_skb_pos;
         i++) {
      t = btf__type_by_id(btf, params[i].type);
      if (!btf_is_ptr(t)) {
        continue;
      }

      t = btf__type_by_id(btf, t->type);
      if (!btf_is_struct(t)) {
        continue;
      }

      st_name = btf__str_by_offset(btf, t->name_off);
      if (strcmp(st_name, "sk_buff") != 0) {
        continue;
      }

      if (!is_vmlinux_btf) {
        btf_fd = btf__fd(btf);
      }

      sinfo.skb_pos = i;
      sinfo.btf_fd = btf_fd;
      sinfo.btf_id = id;

      error = put_sym2info(sdb, func_name, &sinfo);
      if (error != -2 && error != 0) {
        fprintf(stderr, "put_sym2info failed\n");
        return -1;
      }

      if (error != -2) {
        pos2syms_append(sdb, i, func_name);
      }

      break;
    }
  }

  return 0;
}

/*
 * Finds the kernel functions which take struct sk_buff
 * as an argument and record the position of the argument.
 */
static int
fill_sym2info(struct ipft_symsdb *sdb)
{
  int error;
  uint32_t id = 0;
  struct btf *btf, *vmlinux_btf;

  vmlinux_btf = btf__load_vmlinux_btf();
  if (libbpf_get_error(vmlinux_btf) != 0) {
    fprintf(stderr, "libbpf_find_kernel_btf failed\n");
    return -1;
  }

  error = btf_fill_sym2info(sdb, vmlinux_btf, true);
  if (error == -1) {
    fprintf(stderr, "btf_fill_sym2info failed\n");
    return -1;
  }

  /*
   * If kernel doesn't support sysfs BTF, skip loading
   * module BTFs. Unlike vmlinux BTF, libbpf doesn't
   * privide the way to load the kernel module BTFs from
   * ELF files on the disk. Currently, we don't support
   * it because it's difficult to implement it correctly.
   */
  if (access("/sys/kernel/btf/vmlinux", R_OK) != 0) {
    return 0;
  }

  while (true) {
    int fd;

    error = bpf_btf_get_next_id(id, &id);
    if (error && errno == ENOENT) {
      return 0;
    }

    if (error) {
      fprintf(stderr, "bpf_btf_get_next_id failed\n");
      return -1;
    }

    fd = bpf_btf_get_fd_by_id(id);
    if (fd < 0) {
      fprintf(stderr, "bpf_btf_get_fd_by_id failed\n");
      return -1;
    }

    btf = btf__load_from_kernel_by_id_split(id, vmlinux_btf);
    if (btf == NULL) {
      fprintf(stderr, "btf__load_from_kernel_by_id failed\n");
      return -1;
    }

    btf__set_fd(btf, fd);

    error = btf_fill_sym2info(sdb, btf, false);
    if (error == -1) {
      fprintf(stderr, "btf_fill_sym2info failed\n");
      return -1;
    }
  }

  return 0;
}

int
symsdb_create(struct ipft_symsdb **sdbp, struct ipft_symsdb_opt *opt)
{
  int error;
  struct ipft_symsdb *sdb;

  sdb = (struct ipft_symsdb *)calloc(1, sizeof(*sdb));
  if (sdb == NULL) {
    perror("malloc");
    return -1;
  }

  sdb->opt = opt;

  sdb->pos2syms = calloc(opt->max_skb_pos, sizeof(*sdb->pos2syms));
  if (sdb->pos2syms == NULL) {
    perror("calloc");
    return -1;
  }

  for (int i = 0; i < opt->max_skb_pos; i++) {
    kv_init(sdb->pos2syms[i]);
  }

  sdb->availfuncs = kh_init(availfuncs);
  if (sdb->availfuncs == NULL) {
    perror("kh_init");
    return -1;
  }

  error = fill_availfuncs(sdb);
  if (error == -1) {
    fprintf(stderr, "fill_availfuncs failed\n");
    return -1;
  }

  sdb->sym2info = kh_init(sym2info);
  if (sdb->sym2info == NULL) {
    perror("kh_init");
    return -1;
  }

  error = fill_sym2info(sdb);
  if (error == -1) {
    fprintf(stderr, "fill_sym2info failed\n");
    return -1;
  }

  sdb->addr2sym = kh_init(addr2sym);
  if (sdb->addr2sym == NULL) {
    perror("kh_init");
    return -1;
  }

  error = fill_addr2sym(sdb);
  if (error == -1) {
    fprintf(stderr, "fill_addr2sym failed\n");
    return -1;
  }

  *sdbp = (struct ipft_symsdb *)sdb;

  return 0;
}
