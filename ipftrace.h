#pragma once

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

#include <stddef.h>

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

struct ipft {
  struct ipft_symsdb *sdb;
  struct ipft_trace_store *ts;
  struct ipft_symsdb_opt *sopt;
  struct ipft_trace_opt *topt;
};

int ipft_symsdb_create(struct ipft_symsdb **, struct ipft_symsdb_opt *);
char *ipft_symsdb_get_sym(struct ipft_symsdb *, uint64_t);
struct ipft_syminfo *
ipft_symsdb_get_syminfo(struct ipft_symsdb *, char *);
int ipft_symsdb_foreach_syms(struct ipft_symsdb *,
    int (*cb)(const char *, struct ipft_syminfo *, void *), void *);
ptrdiff_t ipft_symsdb_get_mark_offset(struct ipft_symsdb *);
size_t ipft_symsdb_get_total(struct ipft_symsdb *);
int ipft_trace_store_create(struct ipft_trace_store **);
int ipft_trace_add(struct ipft_trace_store *, struct ipft_trace *);
void ipft_trace_dump(struct ipft_trace_store *, char *, FILE *);

#endif
