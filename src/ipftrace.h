#pragma once
#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

/*
 * Max skb position in the function parameters
 */
#define MAX_SKB_POS 5

struct ipft_trace {
  uint64_t skb_addr;
  uint64_t tstamp;
  uint64_t faddr;
  uint32_t processor_id;
  uint8_t _pad[36]; // for future use
  uint8_t data[64];
  /* 128Bytes */
};

struct ipft_ctrl_data {
  uint32_t mark;
  uint32_t mark_offset;
};

struct ipft_symsdb;
struct ipft_tracedb;
struct ipft_debuginfo;

enum log_level {
  IPFT_LOG_INFO = 0,
  IPFT_LOG_WARN = 1,
  IPFT_LOG_ERROR = 2,
  IPFT_LOG_DEBUG = 3,
  IPFT_LOG_MAX
};

struct ipft_opt {
  int verbose;
  uint32_t mark;
  uint32_t mark_offset;
  char *debug_format;
  char *vmlinux_path;
  char *modules_path;
};

struct ipft_syminfo {
  int skb_pos;
};

struct ipft_debuginfo {
  int (*fill_sym2info)(struct ipft_debuginfo *,
      struct ipft_symsdb *);
  int (*sizeof_fn)(struct ipft_debuginfo *,
      const char *, size_t *);
  int (*offsetof_fn)(struct ipft_debuginfo *,
      const char *, const char *, size_t *);
  void (*destroy)(struct ipft_debuginfo *);
};

int symsdb_create(struct ipft_symsdb **sdbp);
void symsdb_destroy(struct ipft_symsdb *sdb);
size_t symsdb_get_sym2info_total(struct ipft_symsdb *sdb);
void symsdb_put_mark_offset(struct ipft_symsdb *sdb, ptrdiff_t mark_offset);
ptrdiff_t symsdb_get_mark_offset(struct ipft_symsdb *sdb);
int symsdb_put_sym2info(struct ipft_symsdb *sdb, char *name, struct ipft_syminfo *sinfo);
int symsdb_get_sym2info(struct ipft_symsdb *sdb, char *name, struct ipft_syminfo **sinfop);
void symsdb_release_all_sym2info(struct ipft_symsdb *sdb);
int symsdb_put_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char *sym);
int symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp);
void symsdb_release_all_addr2sym(struct ipft_symsdb *sdb);
int symsdb_sym2info_foreach(struct ipft_symsdb *sdb,
    int (*cb)(const char *, struct ipft_syminfo *, void *), void *arg);

int tracedb_create(struct ipft_tracedb **tdbp);
void tracedb_destroy(struct ipft_tracedb *tdb);
size_t tracedb_get_total(struct ipft_tracedb *tdb);
int tracedb_put_trace(struct ipft_tracedb *tdb, struct ipft_trace *t);
void tracedb_dump(struct ipft_tracedb *tdb, struct ipft_symsdb *sdb, FILE *f);

int btf_debuginfo_create(struct ipft_debuginfo **dinfop);
int dwarf_debuginfo_create(struct ipft_debuginfo **dinfop);
void debuginfo_destroy(struct ipft_debuginfo *dinfo);
int debuginfo_fill_sym2info(struct ipft_debuginfo *dinfo, struct ipft_symsdb *sdb);
int debuginfo_sizeof(struct ipft_debuginfo *dinfo,
    const char *type, size_t *sizep);
int debuginfo_offsetof(struct ipft_debuginfo *dinfo,
    const char *type, const char *member, size_t *offsetp);

int kallsyms_fill_addr2sym(struct ipft_symsdb *sdb);

void do_trace(struct ipft_opt *);
