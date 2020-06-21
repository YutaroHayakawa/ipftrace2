/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

#define __unused __attribute__((unused))

/*
 * Max skb position in the function parameters
 */
#define MAX_SKB_POS 5

/*
 * Max recursion level
 */
#define MAX_RECURSE_LEVEL 8

struct ipft_symsdb;
struct ipft_tracedb;
struct ipft_script;
struct ipft_bpf_prog;
struct ipft_perf_buffer;
struct ipft_debuginfo;
struct ipft_regex;
struct ipft_traceable_set;

struct ipft_trace {
  uint64_t skb_addr;
  uint64_t tstamp;
  uint64_t faddr;
  uint32_t processor_id;
  uint8_t _pad[36]; // for future use
  uint8_t data[64];
  /* 128Bytes */
} __attribute__((aligned(8)));

struct ipft_tracer_opt {
  uint32_t mark;
  uint32_t mask;
  char *regex;
  char *output_type;
  char *script_path;
  char *debug_info_type;
  size_t perf_page_cnt;
  bool set_rlimit;
};

struct ipft_syminfo {
  int skb_pos;
};

struct ipft_debuginfo {
  int (*fill_sym2info)(struct ipft_debuginfo *, struct ipft_symsdb *);
  int (*sizeof_fn)(struct ipft_debuginfo *, const char *, size_t *);
  int (*offsetof_fn)(struct ipft_debuginfo *, const char *, const char *,
                     size_t *);
  int (*typeof_fn)(struct ipft_debuginfo *, const char *, const char *,
                   char **);
  void (*destroy)(struct ipft_debuginfo *);
};

struct ipft_output {
  struct ipft_symsdb *sdb;
  struct ipft_script *script;
  int (*on_trace)(struct ipft_output *, struct ipft_trace *);
  int (*post_trace)(struct ipft_output *);
  void (*destroy)(struct ipft_output *);
};

int symsdb_create(struct ipft_symsdb **sdbp);
void symsdb_destroy(struct ipft_symsdb *sdb);
size_t symsdb_get_sym2info_total(struct ipft_symsdb *sdb);
int symsdb_put_sym2info(struct ipft_symsdb *sdb, char *name,
                        struct ipft_syminfo *sinfo);
int symsdb_get_sym2info(struct ipft_symsdb *sdb, char *name,
                        struct ipft_syminfo **sinfop);
int symsdb_put_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char *sym);
int symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp);
int symsdb_sym2info_foreach(struct ipft_symsdb *sdb,
                            int (*cb)(const char *, struct ipft_syminfo *,
                                      void *),
                            void *arg);

int tracedb_create(struct ipft_tracedb **tdbp);
void tracedb_destroy(struct ipft_tracedb *tdb);
size_t tracedb_get_total(struct ipft_tracedb *tdb);
int tracedb_put_trace(struct ipft_tracedb *tdb, struct ipft_trace *t);
void tracedb_dump(struct ipft_tracedb *tdb, struct ipft_symsdb *sdb,
                  char *(*cb)(uint8_t *, size_t, void *), void *data);

int debuginfo_create(struct ipft_debuginfo **dinfop, const char *type);
int btf_debuginfo_create(struct ipft_debuginfo **dinfop);
int dwarf_debuginfo_create(struct ipft_debuginfo **dinfop);
void debuginfo_destroy(struct ipft_debuginfo *dinfo);
int debuginfo_fill_sym2info(struct ipft_debuginfo *dinfo,
                            struct ipft_symsdb *sdb);
int debuginfo_sizeof(struct ipft_debuginfo *dinfo, const char *type,
                     size_t *sizep);
int debuginfo_offsetof(struct ipft_debuginfo *dinfo, const char *type,
                       const char *member, size_t *offsetp);
int debuginfo_typeof(struct ipft_debuginfo *dinfo, const char *type,
                     const char *member, char **namep);

int kallsyms_fill_addr2sym(struct ipft_symsdb *sdb);

int script_create(struct ipft_script **scriptp, struct ipft_debuginfo *dinfo,
                  const char *path);
void script_destroy(struct ipft_script *script);
int script_exec_emit(struct ipft_script *script, struct bpf_insn **modp,
                     uint32_t *mod_cnt);
char *script_exec_dump(struct ipft_script *script, uint8_t *data, size_t len);

int perf_buffer_create(struct ipft_perf_buffer **pbp, size_t page_cnt);
void perf_buffer_destroy(struct ipft_perf_buffer *pb);
int perf_buffer_get_fd(struct ipft_perf_buffer *pb, int cpu);
void *perf_buffer_get_base(struct ipft_perf_buffer *pb);
int perf_event_attach_kprobe(const char *name, int prog_fd);
int perf_event_process_mmap_page(struct ipft_perf_buffer *pb,
                                 int (*cb)(struct perf_event_header *, void *),
                                 int cpu, void *data);

int bpf_prog_load(struct ipft_bpf_prog **progp, uint32_t mark, size_t mark_offset,
                  uint32_t mask, struct bpf_insn *mod, uint32_t mod_cnt);
int bpf_prog_get(struct ipft_bpf_prog *prog, int skb_pos);
int bpf_prog_set_perf_fd(struct ipft_bpf_prog *prog, int fd, int cpu);
void bpf_prog_unload(struct ipft_bpf_prog *prog);

int regex_create(struct ipft_regex **rep, const char *regex);
bool regex_match(struct ipft_regex *re, const char *s);
void regex_destroy(struct ipft_regex *re);

int output_create(struct ipft_output **outp, const char *type,
    struct ipft_symsdb *sdb, struct ipft_script *script);
int aggregate_output_create(struct ipft_output **outp);
int stream_output_create(struct ipft_output **outp);
int output_on_trace(struct ipft_output *out, struct ipft_trace *t);
int output_post_trace(struct ipft_output *out);
void output_destroy(struct ipft_output *out);

int traceable_set_create(struct ipft_traceable_set **tsetp);
bool traceable_set_is_traceable(struct ipft_traceable_set *tset, const char *sym);
void traceable_set_destroy(struct ipft_traceable_set *tset);

int tracer_run(struct ipft_tracer_opt *opt);
int list_functions(struct ipft_tracer_opt *opt);
int test_bpf_prog(struct ipft_tracer_opt *opt);
