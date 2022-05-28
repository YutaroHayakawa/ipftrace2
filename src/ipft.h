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
struct ipft_tracer;

struct ipft_event {
  uint64_t packet_id;
  uint64_t tstamp;
  uint64_t faddr;
  uint32_t processor_id;
  uint8_t is_return;
  uint8_t _pad[35]; // for future use
  uint8_t data[64];
  /* 128Bytes */
} __attribute__((aligned(8)));

struct ipft_trace_config {
  uint32_t mark;
  uint32_t mask;
};

struct ipft_tracer_opt {
  char *backend;
  uint32_t mark;
  uint32_t mask;
  char *regex;
  char *script;
  char *tracer;
  char *output_type;
  size_t perf_page_cnt;
  uint64_t perf_sample_period;
  uint32_t perf_wakeup_events;
  bool verbose;
  bool enable_probe_server;
  uint16_t probe_server_port;
};

struct ipft_syminfo {
  int skb_pos;
  uint32_t btf_fd;
  uint32_t btf_id;
};

struct ipft_output {
  char *tracer;
  struct ipft_symsdb *sdb;
  struct ipft_script *script;
  int (*on_event)(struct ipft_output *, struct ipft_event *);
  int (*post_trace)(struct ipft_output *);
};

int symsdb_create(struct ipft_symsdb **sdbp);
size_t symsdb_get_sym2info_total(struct ipft_symsdb *sdb);
int symsdb_get_sym2info(struct ipft_symsdb *sdb, const char *name,
                        struct ipft_syminfo **sinfop);
int symsdb_get_addr2sym(struct ipft_symsdb *sdb, uint64_t addr, char **symp);
int symsdb_sym2info_foreach(struct ipft_symsdb *sdb,
                            int (*cb)(const char *, struct ipft_syminfo *,
                                      void *),
                            void *arg);
const char *symsdb_pos2syms_get(struct ipft_symsdb *sdb, int pos, int idx);
int symsdb_get_pos2syms_total(struct ipft_symsdb *sdb, int pos);

int regex_create(struct ipft_regex **rep, const char *regex);
bool regex_match(struct ipft_regex *re, const char *s);

int script_create(struct ipft_script **scriptp, const char *path);
int script_get_program(struct ipft_script *script, uint8_t **imagep,
                       size_t *image_sizep);
int script_exec_decode(struct ipft_script *script, uint8_t *data, size_t len,
                       int (*cb)(const char *, size_t, const char *, size_t));
void script_exec_fini(struct ipft_script *script);

int output_create(struct ipft_output **outp, const char *type,
                  struct ipft_symsdb *sdb, struct ipft_script *script,
                  char *tracer);
int aggregate_output_create(struct ipft_output **outp);
int json_output_create(struct ipft_output **outp);
int output_on_trace(struct ipft_output *out, struct ipft_event *e);
int output_post_trace(struct ipft_output *out);

int tracer_create(struct ipft_tracer **tp, struct ipft_tracer_opt *opt);
int tracer_run(struct ipft_tracer *t);
int list_functions(struct ipft_tracer_opt *opt);
