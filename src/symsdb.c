#include <ctype.h>
#include <linux/bpf.h>
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

KHASH_MAP_INIT_INT64(addr2sym, struct ipft_sym *)
KHASH_MAP_INIT_STR(symname2addr, uint64_t)
KHASH_MAP_INIT_STR(availfuncs, int)
KHASH_SET_INIT_STR(funcsseen)

struct ipft_symsdb {
  struct ipft_symsdb_opt *opt;
  khash_t(funcsseen) * funcsseen;
  khash_t(availfuncs) * availfuncs;
  kvec_t(struct ipft_sym *) * pos2syms;
  khash_t(addr2sym) * addr2symname;
  khash_t(symname2addr) * symname2addr;
};

static int
pos2syms_append(struct ipft_symsdb *sdb, int pos, struct ipft_sym *sym)
{
  struct ipft_sym *v;

  v = malloc(sizeof(*v));
  if (v == NULL) {
    ERROR("malloc failed\n");
    return -1;
  }

  memcpy(v, sym, sizeof(*sym));

  kv_push(struct ipft_sym *, sdb->pos2syms[pos], v);

  return 0;
}

struct ipft_sym **
symsdb_get_syms_by_pos(struct ipft_symsdb *sdb, int pos)
{
  return sdb->pos2syms[pos].a;
}

int
symsdb_get_syms_total(struct ipft_symsdb *sdb)
{
  int ret = 0;
  for (int i = 0; i < sdb->opt->max_skb_pos; i++) {
    ret += kv_size(sdb->pos2syms[i]);
  }
  return ret;
}

int
symsdb_get_syms_total_by_pos(struct ipft_symsdb *sdb, int pos)
{
  return kv_size(sdb->pos2syms[pos]);
}

static int
put_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char *symname,
             char *modname)
{
  int error;
  khint_t iter;
  struct ipft_sym *sym;
  khash_t(addr2sym) * db;

  sym = calloc(1, sizeof(*sym));
  if (sym == NULL) {
    return -1;
  }

  sym->symname = strdup(symname);
  if (sym->symname == NULL) {
    return -1;
  }

  sym->modname = strdup(modname);
  if (sym->modname == NULL) {
    return -1;
  }

  db = ((struct ipft_symsdb *)sdb)->addr2symname;

  iter = kh_put(addr2sym, db, addr, &error);
  if (error == -1) {
    return -1;
  } else if (error == 0) {
    VERBOSE("Duplicated address found %p for symbol %s at module %s\n",
            (void *)addr, symname, modname);
    return 0;
  }

  kh_value(db, iter) = sym;

  return 0;
}

struct ipft_sym unknown_sym = {
    .modname = "(unknown)",
    .symname = "(unknown)",
};

int
symsdb_get_sym_by_addr(struct ipft_symsdb *sdb, uint64_t addr,
                       struct ipft_sym **symp)
{
  khint_t iter;
  khash_t(addr2sym) * db;

  db = ((struct ipft_symsdb *)sdb)->addr2symname;

  iter = kh_get(addr2sym, db, addr);
  if (iter == kh_end(db)) {
#ifdef __x86_64__
    /* Symbol not found. This can be because of the kernel issue that
     * bpf_get_func_ip() misbehaves when Intel IBT is enabled. Retry symbol
     * resolution with the address excluding the ENDBR instruction. Ref:
     * https://lore.kernel.org/bpf/20220811091526.172610-5-jolsa@kernel.org/
     */
    iter = kh_get(addr2sym, db, addr - 4);
    if (iter != kh_end(db)) {
      goto out;
    }
#endif
    *symp = &unknown_sym;
    return -1;
  }

out:
  *symp = kh_value(db, iter);
  return 0;
}

static int
put_symname2addr(struct ipft_symsdb *sdb, const char *symname, uint64_t addr)
{
  char *k;
  int missing;
  khint_t iter;
  khash_t(symname2addr) * db;

  k = strdup(symname);
  if (k == NULL) {
    ERROR("strdup failed\n");
    return -1;
  }

  db = ((struct ipft_symsdb *)sdb)->symname2addr;

  iter = kh_put(symname2addr, db, k, &missing);
  if (missing == -1) {
    ERROR("kh_put failed\n");
    return -1;
  } else if (!missing) {
    free(k);
  }

  kh_value(db, iter) = addr;

  return 0;
}

static int
get_addr_by_symname(struct ipft_symsdb *sdb, char *symname, uint64_t *addrp)
{
  khint_t iter;
  khash_t(symname2addr) * db;

  db = ((struct ipft_symsdb *)sdb)->symname2addr;

  iter = kh_get(symname2addr, db, symname);
  if (iter == kh_end(db)) {
    ERROR("Failed to resolve func symbol name: %s\n", symname);
    return -1;
  }

  *addrp = kh_value(db, iter);

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
    ERROR("kh_put failed\n");
    return -1;
  } else if (!missing) {
    free(k);
  }

  return 0;
}

static bool
func_is_available(struct ipft_symsdb *sdb, const char *symname)
{
  khint_t iter;

  iter = kh_get(availfuncs, sdb->availfuncs, symname);
  if (iter == kh_end(sdb->availfuncs)) {
    return false;
  }

  return true;
}

static int
put_funcsseen(struct ipft_symsdb *sdb, char *sym)
{
  int missing;
  __unused khint_t iter;

  iter = kh_put(funcsseen, sdb->funcsseen, sym, &missing);
  if (missing == -1) {
    ERROR("kh_put failed\n");
    return -1;
  }

  return 0;
}

static bool
func_seen(struct ipft_symsdb *sdb, const char *symname)
{
  khint_t iter;

  iter = kh_get(funcsseen, sdb->funcsseen, symname);
  if (iter == kh_end(sdb->funcsseen)) {
    return false;
  }

  return true;
}

static int
populate_availfuncs(struct ipft_symsdb *sdb)
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
          ERROR("put_availfuncs failed\n");
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
populate_addr2symname_and_symname2addr(struct ipft_symsdb *sdb)
{
  FILE *f;
  int error;
  uint64_t addr;
  char line[2048];
  char *symname, *endsym;
  char *modname, *endmod;

  f = fopen("/proc/kallsyms", "r");
  if (f == NULL) {
    perror("fopen");
    return -1;
  }

  if (geteuid() != 0) {
    ERROR(
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

    modname = endsym;
    while (*modname && isspace(*modname)) {
      modname++;
    }

    if (*modname == '[') {
      endmod = modname;
      modname++;
      while (*endmod && *endmod != ']') {
        endmod++;
      }
      if (*endmod != ']') {
        modname = "(unknown)";
      }
      *endmod = '\0';
    } else {
      modname = "vmlinux";
    }

    *endsym = '\0';

    /*
     * Only add the symbols which are available
     */
    if (!func_is_available(sdb, symname)) {
      continue;
    }

    /*
     * This shouldn't fail
     */
    error = put_addr2sym(sdb, addr, symname, modname);
    if (error == -1) {
      ERROR("put_addr2sym failed\n");
      return -1;
    }

    error = put_symname2addr(sdb, symname, addr);
    if (error == -1) {
      ERROR("put_symname2addr failed\n");
      return -1;
    }
  }

  fclose(f);

  return 0;
}

static int
do_populate_syms(struct ipft_symsdb *sdb, const char *modname, struct btf *btf,
                 bool is_vmlinux_btf)
{
  uint64_t addr;
  struct ipft_sym sym;
  int error, btf_fd = 0;
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

      if (func_seen(sdb, func_name)) {
        continue;
      }

      sym.symname = strdup(func_name);
      if (sym.symname == NULL) {
        ERROR("strdup failed\n");
        return -1;
      }

      if (modname != NULL) {
        sym.modname = strdup(modname);
        if (sym.modname == NULL) {
          ERROR("strdup failed\n");
          return -1;
        }
      } else {
        sym.modname = NULL;
      }

      error = get_addr_by_symname(sdb, sym.symname, &addr);
      if (error == -1) {
        ERROR("get_addr_by_symname failed\n");
        return -1;
      }

      sym.addr = addr;
      sym.btf_fd = btf_fd;
      sym.btf_id = id;

      error = pos2syms_append(sdb, i, &sym);
      if (error == -1) {
        ERROR("pos2syms_append failed\n");
        return -1;
      }

      error = put_funcsseen(sdb, sym.symname);
      if (error == -1) {
        ERROR("put_funcsseen failed\n");
        return -1;
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
populate_syms(struct ipft_symsdb *sdb)
{
  int error;
  uint32_t id = 0;
  struct btf *btf, *vmlinux_btf;

  vmlinux_btf = btf__load_vmlinux_btf();
  if (libbpf_get_error(vmlinux_btf) != 0) {
    ERROR("libbpf_find_kernel_btf failed\n");
    return -1;
  }

  error = do_populate_syms(sdb, "vmlinux", vmlinux_btf, true);
  if (error == -1) {
    ERROR("btf_fill_sym2info failed\n");
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
    char name[64] = {0};
    struct bpf_btf_info info = {0};
    uint32_t info_len = sizeof(info);

    info.name = (__u64)name;
    info.name_len = sizeof(name);

    error = bpf_btf_get_next_id(id, &id);
    if (error && errno == ENOENT) {
      return 0;
    }

    if (error) {
      ERROR("bpf_btf_get_next_id failed\n");
      return -1;
    }

    fd = bpf_btf_get_fd_by_id(id);
    if (fd < 0) {
      ERROR("bpf_btf_get_fd_by_id failed\n");
      return -1;
    }

    error = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    if (error == -1) {
      ERROR("bpf_obj_get_info_by_fd failed: %s\n", strerror(errno));
      return -1;
    }

    btf = btf__load_from_kernel_by_id_split(id, vmlinux_btf);
    if (btf == NULL) {
      ERROR("btf__load_from_kernel_by_id failed\n");
      return -1;
    }

    btf__set_fd(btf, fd);

    error = do_populate_syms(sdb, (const char *)info.name, btf, false);
    if (error == -1) {
      ERROR("btf_fill_sym2info failed\n");
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
    ERROR("calloc failed\n");
    return -1;
  }

  sdb->opt = opt;

  sdb->availfuncs = kh_init(availfuncs);
  if (sdb->availfuncs == NULL) {
    ERROR("kh_init failed\n");
    return -1;
  }

  error = populate_availfuncs(sdb);
  if (error == -1) {
    ERROR("populate_availfuncs failed\n");
    return -1;
  }

  sdb->addr2symname = kh_init(addr2sym);
  if (sdb->addr2symname == NULL) {
    ERROR("kh_init failed\n");
    return -1;
  }

  sdb->symname2addr = kh_init(symname2addr);
  if (sdb->symname2addr == NULL) {
    ERROR("kh_init failed\n");
    return -1;
  }

  error = populate_addr2symname_and_symname2addr(sdb);
  if (error == -1) {
    ERROR("populate_addr2symname failed\n");
    return -1;
  }

  sdb->funcsseen = kh_init(funcsseen);
  if (sdb->funcsseen == NULL) {
    ERROR("kh_init failed\n");
    return -1;
  }

  sdb->pos2syms = calloc(opt->max_skb_pos, sizeof(*sdb->pos2syms));
  if (sdb->pos2syms == NULL) {
    ERROR("calloc failed\n");
    return -1;
  }

  for (int i = 0; i < opt->max_skb_pos; i++) {
    kv_init(sdb->pos2syms[i]);
  }

  error = populate_syms(sdb);
  if (error == -1) {
    ERROR("populate_pos2syms failed\n");
    return -1;
  }

  *sdbp = (struct ipft_symsdb *)sdb;

  return 0;
}
