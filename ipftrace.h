#pragma once

#define __unused __attribute__((unused))

struct ipft_symsdb;

struct ipft_trace {
  uint64_t skb_addr;
  uint64_t tstamp;
  uint64_t faddr;
};

struct ipft_ctrl_data {
  uint32_t mark;
  uint32_t mark_offset;
};

#ifndef BPF

struct ipft_symsdb;
struct ipft_trace_store;

struct ipft_trace_opt {
  uint32_t mark;
};

struct ipft_symsdb_opt {
  char *format;
  char *vmlinux_path;
  char *modules_path;
};

struct ipft_syminfo {
  int skb_pos;
};

int ipft_symsdb_create(struct ipft_symsdb **sdbp);
void ipft_symsdb_destroy(struct ipft_symsdb *sdb);
void symsdb_put_mark_offset(struct ipft_symsdb *sdb, ptrdiff_t mark_offset);
ptrdiff_t symsdb_get_mark_offset(struct ipft_symsdb *sdb);
int symsdb_put_sym2info(struct ipft_symsdb *sdb, char *name, struct ipft_syminfo *sinfo);
int symsdb_get_sym2info(struct ipft_symsdb *sdb, char *name, struct ipft_syminfo **sinfop);
void symsdb_release_all_sym2info(struct ipft_symsdb *sdb);
int symsdb_put_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char *sym);
int symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp);
void symsdb_release_all_addr2sym(struct ipft_symsdb *sdb);

struct ipft_syminfo *
ipft_symsdb_get_syminfo(struct ipft_symsdb *, char *);
int ipft_symsdb_foreach_syms(struct ipft_symsdb *,
    int (*cb)(const char *, struct ipft_syminfo *, void *), void *);
ptrdiff_t ipft_symsdb_get_mark_offset(struct ipft_symsdb *);
size_t ipft_symsdb_get_total(struct ipft_symsdb *);
int ipft_trace_store_create(struct ipft_trace_store **);
size_t ipft_trace_total(struct ipft_trace_store *);
int ipft_trace_add(struct ipft_trace_store *, struct ipft_trace *);
void ipft_trace_dump(struct ipft_trace_store *, struct ipft_symsdb *sdb, FILE *);

#endif
