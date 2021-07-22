/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/perf_event.h>

#include <uapi/linux/bpf.h>

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
  size_t perf_page_cnt;
  uint64_t perf_sample_period;
  uint32_t perf_wakeup_events;
  bool set_rlimit;
  bool verbose;
};

struct ipft_syminfo {
  int skb_pos;
};

struct ipft_output {
  struct ipft_symsdb *sdb;
  struct ipft_script *script;
  int (*on_trace)(struct ipft_output *, struct ipft_trace *);
  int (*post_trace)(struct ipft_output *);
};

int symsdb_create(struct ipft_symsdb **sdbp);
size_t symsdb_get_sym2info_total(struct ipft_symsdb *sdb);
int symsdb_get_sym2info(struct ipft_symsdb *sdb, char *name,
                        struct ipft_syminfo **sinfop);
int symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp);
int symsdb_sym2info_foreach(struct ipft_symsdb *sdb,
                            int (*cb)(const char *, struct ipft_syminfo *,
                                      void *),
                            void *arg);

int regex_create(struct ipft_regex **rep, const char *regex);
bool regex_match(struct ipft_regex *re, const char *s);

int script_create(struct ipft_script **scriptp, const char *path);
int script_exec_emit(struct ipft_script *script, uint8_t **imagep,
                     size_t *image_sizep);
char *script_exec_dump(struct ipft_script *script, uint8_t *data, size_t len);
void script_exec_fini(struct ipft_script *script);

int output_create(struct ipft_output **outp, const char *type,
                  struct ipft_symsdb *sdb, struct ipft_script *script);
int aggregate_output_create(struct ipft_output **outp);
int stream_output_create(struct ipft_output **outp);
int output_on_trace(struct ipft_output *out, struct ipft_trace *t);
int output_post_trace(struct ipft_output *out);

int traceable_set_create(struct ipft_traceable_set **tsetp);
bool traceable_set_is_traceable(struct ipft_traceable_set *tset,
                                const char *sym);

int tracer_run(struct ipft_tracer_opt *opt);
int list_functions(struct ipft_tracer_opt *opt);
