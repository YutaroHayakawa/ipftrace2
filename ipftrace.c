#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipftrace.h"
#include "ipftrace.elf.h"

#define ERROR_BUF_SIZE 256

enum log_level {
  IPFT_LOG_DEBUG = 0,
  IPFT_LOG_INFO = 1,
  IPFT_LOG_WARN = 2,
  IPFT_LOG_ERROR = 3
};

struct attach_stat {
  size_t total;
  size_t attached;
  size_t failed;
};

struct trace_stat {
  size_t packets;
  size_t funcs;
};

struct ipft {
  int verbose;
  struct bpf_object *bpf;
  struct ipft_symsdb *sdb;
  struct ipft_trace_store *ts;
  struct ipft_symsdb_opt *sopt;
  struct ipft_trace_opt *topt;
};

static char error_buf[ERROR_BUF_SIZE] = {};

static int pr_suppress_warn(enum libbpf_print_level level,
    const char *format, va_list args) {
  if (level == LIBBPF_WARN) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

static struct bpf_object *
bpf_object_open_and_load(unsigned char *buf, size_t len, char *name)
{
  int error;
  struct bpf_object *bpf;

  bpf = bpf_object__open_buffer(buf, len, name);
  if ((error = libbpf_get_error(bpf)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__open_mem: %s\n", error_buf);
    return NULL;
  }

  error = bpf_object__load(bpf);
  if (error != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__load: %s\n", error_buf);
    bpf_object__close(bpf);
    return NULL;
  }

  return bpf;
}

static int
set_ctrl_data(struct bpf_object *bpf,
    uint32_t mark, uint32_t mark_offset)
{
  int error, fd;
  struct ipft_ctrl_data cdata;

  fd = bpf_object__find_map_fd_by_name(bpf, "ctrl_map");
  if (fd < 0) {
    libbpf_strerror(-fd, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_map_by_name: %s\n", error_buf);
    return -1;
  }

  cdata.mark = mark;
  cdata.mark_offset = mark_offset;

  error = bpf_map_update_elem(fd, &(int){0}, &cdata, BPF_ANY);
  if (error != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_map_update_elem: %s\n", error_buf);
    return -1;
  }

  return 0;
}

struct attach_ctx {
  int verbose;
  size_t total;
  size_t attached;
  size_t failed;
  struct bpf_object *bpf;
  struct bpf_program *main1;
  struct bpf_program *main2;
  struct bpf_program *main3;
  struct bpf_program *main4;
  struct ipft_symsdb *sdb;
};

#define ATTACH_FMT "Attaching %zu probes (Attached: %zu Failed: %zu)\r"

static int
attach_kprobe(const char *sym, struct ipft_syminfo *si, void *arg)
{
  struct attach_ctx *ctx;
  struct bpf_link *link;
  libbpf_print_fn_t orig_fn;

  ctx = (struct attach_ctx *)arg;

  if (ctx->verbose <= IPFT_LOG_WARN) {
    orig_fn = libbpf_set_print(pr_suppress_warn);
  } else {
    orig_fn = NULL;
  }

  switch (si->skb_pos) {
    case 1:
      link = bpf_program__attach_kprobe(ctx->main1, false, sym);
      break;
    case 2:
      link = bpf_program__attach_kprobe(ctx->main2, false, sym);
      break;
    case 3:
      link = bpf_program__attach_kprobe(ctx->main3, false, sym);
      break;
    case 4:
      link = bpf_program__attach_kprobe(ctx->main4, false, sym);
      break;
    default:
      fprintf(stderr, "Invalid skb position\n");
      return -1;
  }

  if (libbpf_get_error(link) == 0) {
    ctx->attached++;
  } else {
    ctx->failed++;
  }

  printf(ATTACH_FMT, ctx->total, ctx->attached, ctx->failed);

  if (orig_fn != NULL) {
    libbpf_set_print(orig_fn);
  }

  return 0;
}

static int
attach_probes(struct bpf_object *bpf, struct ipft_symsdb *sdb, int verbose)
{
  int error;
  struct attach_ctx ctx;

  ctx.verbose = verbose;
  ctx.bpf = bpf;
  ctx.total = ipft_symsdb_get_total(sdb);
  ctx.attached = 0;
  ctx.failed = 0;

  ctx.main1 = bpf_object__find_program_by_name(bpf, "ipftrace_main1");
  ctx.main2 = bpf_object__find_program_by_name(bpf, "ipftrace_main2");
  ctx.main3 = bpf_object__find_program_by_name(bpf, "ipftrace_main3");
  ctx.main4 = bpf_object__find_program_by_name(bpf, "ipftrace_main4");

  if ((error = libbpf_get_error(ctx.main1)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_program_by_title: %s\n", error_buf);
    return -1;
  }

  error = ipft_symsdb_foreach_syms(sdb, attach_kprobe, &ctx);
  if (error != 0) {
    fprintf(stderr, "Failed to attach kprobe\n");
    return -1;
  }

  printf("\n");

  return 0;
}

struct trace_ctx {
  struct ipft_trace_store *ts;
};

static void
on_event(void *_ctx, __unused int cpu, void *data, __u32 size)
{
  int error;
  struct ipft_trace *trace;
  struct trace_ctx *ctx;

  if (size != sizeof(*trace)) {
    fprintf(stderr, "Invalid trace size %u, it should be %zu",
        size, sizeof(*trace));
    return;
  }

  ctx = (struct trace_ctx *)_ctx;
  trace = (struct ipft_trace *)data;

  error = ipft_trace_add(ctx->ts, trace);
  if (error != 0) {
    fprintf(stderr, "Failed to add trace: %s\n", strerror(error));
  }

  printf("Captured %lu sk_buffs\r", ipft_trace_total(ctx->ts));
}

static void
on_lost(__unused void *ctx, __unused int cpu, __u64 cnt)
{
  fprintf(stderr, "%llu events lost\n", cnt);
}

static bool trace_finish = false;

static void
on_sigint(__unused int sig)
{
  trace_finish = true;
}

static int
run_trace(struct bpf_object *bpf, struct ipft_trace_store *ts)
{
  int error, fd;
  struct trace_ctx ctx;
  struct perf_buffer *pb;
  struct perf_buffer_opts pb_opts;

  fd = bpf_object__find_map_fd_by_name(bpf, "events");
  if (fd < 0) {
    libbpf_strerror(-fd, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_map_by_name: %s\n", error_buf);
    return -1;
  }

  ctx.ts = ts;

  pb_opts.sample_cb = on_event;
  pb_opts.lost_cb = on_lost;
  pb_opts.ctx = &ctx;

  signal(SIGINT, on_sigint);

  pb = perf_buffer__new(fd, 64, &pb_opts);
  if ((error = libbpf_get_error(pb)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "perf_buffer__new: %s\n", error_buf);
    return -1;
  }

  while ((error = perf_buffer__poll(pb, 100)) >= 0) {
    if (trace_finish) {
      break;
    }
  }

  return 0;
}

static void
do_trace(struct ipft *ipft)
{
  int error;
  struct bpf_object *bpf;

  bpf = bpf_object_open_and_load(ipftrace_bpf_o,
      ipftrace_bpf_o_len, "ipftrace2");
  if (bpf == NULL) {
    fprintf(stderr, "Failed to open and load BPF object\n");
    exit(EXIT_FAILURE);
  }

  error = set_ctrl_data(bpf, ipft->topt->mark,
      ipft_symsdb_get_mark_offset(ipft->sdb));
  if (error == -1) {
    fprintf(stderr, "Failed to set control data\n");
    exit(EXIT_FAILURE);
  }

  error = attach_probes(bpf, ipft->sdb, ipft->verbose);
  if (error == -1) {
    fprintf(stderr, "Failed to attach probes\n");
    exit(EXIT_FAILURE);
  }

  error = run_trace(bpf, ipft->ts);
  if (error == -1) {
    fprintf(stderr, "Error occured while running the trace\n");
    exit(EXIT_FAILURE);
  }

  ipft_trace_dump(ipft->ts, ipft->sdb, stdout);

  bpf_object__close(bpf);
}

static struct option options[] = {
  { "--mark",    required_argument, 0, 'm' },
  { "--format",  required_argument, 0, 'f' },
  { "--verbose", required_argument, 0, 'v' },
};

static void
usage(void)
{
  fprintf(stderr,
      "Usage: ipftrace [OPTIONS]\n"
      "\n"
      "Options:\n"
      " -f, --format <dwarf|btf>   Debug information to use\n"
      " -m, --mark <mark>          Trace the packet marked with <mark> [required]\n"
      "\n");
  exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
  struct ipft ipft = {};
  int error, opt, optind;
  struct ipft_symsdb *sdb = NULL;
  struct ipft_trace_opt topt = {};
  struct ipft_symsdb_opt sopt = {};
  struct ipft_trace_store *ts = NULL;

  while ((opt = getopt_long(argc, argv, "m:f:v:",
          options, &optind)) != -1) {
    switch (opt) {
    case 'm':
      topt.mark = strtoul(optarg, NULL, 16);
      break;
    case 'f':
      sopt.format = strdup(optarg);
      break;
    case 'v':
      ipft.verbose = atoi(optarg);
      break;
    default:
      usage();
      break;
    }
  }

  if (topt.mark == 0) {
    fprintf(stderr, "Mark (-m, --mark) is not specified\n\n");
    usage();
  }

  if (sopt.format == NULL) {
    sopt.format = "dwarf";
  }

  error = ipft_symsdb_create(&sdb, &sopt);
  if (error != 0) {
    fprintf(stderr, "ipft_symsdb_create: %s\n", strerror(error));
    return EXIT_SUCCESS;
  }

  error = ipft_trace_store_create(&ts);
  if (error != 0) {
    fprintf(stderr, "ipft_trace_store_create: %s\n", strerror(error));
    return EXIT_SUCCESS;
  }

  ipft.sdb = sdb;
  ipft.ts = ts;
  ipft.sopt = &sopt;
  ipft.topt = &topt;

  do_trace(&ipft);

  return EXIT_SUCCESS;
}
