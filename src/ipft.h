#pragma once
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <linux/perf_event.h>

#include <uapi/linux/bpf.h>

#include "ipft_common.h"

#define __unused __attribute__((unused))

/*
 * Max skb position in the function parameters
 */
#define KPROBE_MAX_SKB_POS 5
#define FTRACE_MAX_SKB_POS 12
#define KPROBE_MAX_ARGS INT_MAX // no limit
#define FTRACE_MAX_ARGS 12

/*
 * Max recursion level
 */
#define MAX_RECURSE_LEVEL 8

struct ipft_symsdb;
struct ipft_regex;
struct ipft_script;
struct ipft_tracer;

enum ipft_tracers {
  IPFT_TRACER_UNSPEC,
  IPFT_TRACER_FUNCTION,
  IPFT_TRACER_FUNCTION_GRAPH,
};

enum ipft_backends {
  IPFT_BACKEND_UNSPEC,
  IPFT_BACKEND_KPROBE,
  IPFT_BACKEND_FTRACE,
  IPFT_BACKEND_KPROBE_MULTI,
};

enum ipft_outputs {
  IPFT_OUTPUT_UNSPEC,
  IPFT_OUTPUT_AGGREGATE,
  IPFT_OUTPUT_JSON,
};

struct ipft_tracer_opt {
  enum ipft_tracers tracer;
  enum ipft_backends backend;
  uint32_t mark;
  uint32_t mask;
  char *regex;
  char *script;
  enum ipft_outputs output;
  size_t perf_page_cnt;
  uint64_t perf_sample_period;
  uint32_t perf_wakeup_events;
  bool verbose;
  bool enable_probe_server;
  uint16_t probe_server_port;
};

struct ipft_symsdb_opt {
  int max_args;
  int max_skb_pos;
};

struct ipft_sym {
  uint64_t addr;
  char *symname;
  uint32_t btf_fd;
  uint32_t btf_id;
};

struct ipft_output {
  enum ipft_tracers tracer;
  struct ipft_symsdb *sdb;
  struct ipft_script *script;
  int (*on_event)(struct ipft_output *, struct ipft_event *);
  int (*post_trace)(struct ipft_output *);
};

enum ipft_tracers get_tracer_id_by_name(const char *name);
const char *get_tracer_name_by_id(enum ipft_tracers tracer);
enum ipft_backends get_backend_id_by_name(const char *name);
const char *get_backend_name_by_id(enum ipft_backends backend);
enum ipft_backends select_backend_for_tracer(enum ipft_tracers tracer);
int get_max_args_for_backend(enum ipft_backends backend);
int get_max_skb_pos_for_backend(enum ipft_backends backend);

int symsdb_create(struct ipft_symsdb **sdbp, struct ipft_symsdb_opt *opt);
int symsdb_get_symname_by_addr(struct ipft_symsdb *sdb, uint64_t addr,
                               char **symnamep);
struct ipft_sym **symsdb_get_syms_by_pos(struct ipft_symsdb *sdb, int pos);
int symsdb_get_syms_total(struct ipft_symsdb *sdb);
int symsdb_get_syms_total_by_pos(struct ipft_symsdb *sdb, int pos);

int regex_create(struct ipft_regex **rep, const char *regex);
bool regex_match(struct ipft_regex *re, const char *s);

int script_create(struct ipft_script **scriptp, const char *path);
int script_get_program(struct ipft_script *script, uint8_t **imagep,
                       size_t *image_sizep);
int script_exec_decode(struct ipft_script *script, uint8_t *data, size_t len,
                       int (*cb)(const char *, size_t, const char *, size_t));
void script_exec_fini(struct ipft_script *script);

const char *get_output_name_by_id(enum ipft_outputs id);
enum ipft_outputs get_output_id_by_name(const char *name);
int output_create(struct ipft_output **outp, enum ipft_outputs output,
                  struct ipft_symsdb *sdb, struct ipft_script *script,
                  enum ipft_tracers tracer);
int aggregate_output_create(struct ipft_output **outp);
int json_output_create(struct ipft_output **outp);
int output_on_trace(struct ipft_output *out, struct ipft_event *e);
int output_post_trace(struct ipft_output *out);

int tracer_create(struct ipft_tracer **tp, struct ipft_tracer_opt *opt);
int tracer_run(struct ipft_tracer *t);
int list_functions(struct ipft_tracer_opt *opt);
int probe_kprobe_multi(void);
char *libbpf_error_string(int error);
