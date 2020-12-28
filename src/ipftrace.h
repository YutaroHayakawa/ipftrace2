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
struct ipft_debuginfo;
struct ipft_regex;
struct ipft_script;
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

struct ipft_trace_config {
  uint32_t mark;
  uint32_t mask;
};

struct ipft_tracer_opt {
  uint32_t mark;
  uint32_t mask;
  char *regex;
  char *script;
  char *output_type;
  char *debug_info_type;
  size_t perf_page_cnt;
  bool set_rlimit;
};

struct ipft_syminfo {
  int skb_pos;
};

struct ipft_debuginfo {
  int (*fill_sym2info)(struct ipft_debuginfo *, struct ipft_symsdb *);
};

struct ipft_output {
  struct ipft_symsdb *sdb;
  struct ipft_script *script;
  int (*on_trace)(struct ipft_output *, struct ipft_trace *);
  int (*post_trace)(struct ipft_output *);
};

int symsdb_create(struct ipft_symsdb **sdbp);
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
size_t tracedb_get_total(struct ipft_tracedb *tdb);
int tracedb_put_trace(struct ipft_tracedb *tdb, struct ipft_trace *t);
void tracedb_dump(struct ipft_tracedb *tdb, struct ipft_symsdb *sdb,
    struct ipft_script *script);

int debuginfo_create(struct ipft_debuginfo **dinfop);
int btf_debuginfo_create(struct ipft_debuginfo **dinfop);
int debuginfo_fill_sym2info(struct ipft_debuginfo *dinfo,
                            struct ipft_symsdb *sdb);

int kallsyms_fill_addr2sym(struct ipft_symsdb *sdb);

int regex_create(struct ipft_regex **rep, const char *regex);
bool regex_match(struct ipft_regex *re, const char *s);

int script_create(struct ipft_script **scriptp, const char *path);
int script_exec_emit(struct ipft_script *script,
    uint8_t **imagep, size_t *image_sizep);
char *script_exec_dump(struct ipft_script *script, uint8_t *data, size_t len);
void script_exec_fini(struct ipft_script *script);

int output_create(struct ipft_output **outp, const char *type,
    struct ipft_symsdb *sdb, struct ipft_script *script);
int aggregate_output_create(struct ipft_output **outp);
int stream_output_create(struct ipft_output **outp);
int output_on_trace(struct ipft_output *out, struct ipft_trace *t);
int output_post_trace(struct ipft_output *out);

int traceable_set_create(struct ipft_traceable_set **tsetp);
bool traceable_set_is_traceable(struct ipft_traceable_set *tset, const char *sym);

int tracer_run(struct ipft_tracer_opt *opt);
int list_functions(void);
