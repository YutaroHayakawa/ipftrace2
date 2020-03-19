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

enum debug_level {
  IPFT_DEBUG_DEBUG = 0,
  IPFT_DEBUG_INFO = 1,
  IPFT_DEBUG_WARN = 2,
  IPFT_DEBUG_ERROR = 3
};

struct attach_stat {
  size_t total;
  size_t attached;
  size_t failed;
};

struct ipft {
  int verbose;
  struct bpf_object *bpf;
  struct attach_stat astat;
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

#define ATTACH_FMT "Attaching %zu probes (Attached: %zu Failed: %zu)\r"

static int
attach_kprobe(const char *sym, struct ipft_syminfo *si, void *arg)
{
  int error;
  struct ipft *ipft;
  struct bpf_link *link;
  libbpf_print_fn_t orig_fn;
  struct bpf_program *main1, *main2, *main3, *main4;

  ipft = (struct ipft *)arg;

  main1 = bpf_object__find_program_by_name(ipft->bpf, "ipftrace_main1");
  main2 = bpf_object__find_program_by_name(ipft->bpf, "ipftrace_main2");
  main3 = bpf_object__find_program_by_name(ipft->bpf, "ipftrace_main3");
  main4 = bpf_object__find_program_by_name(ipft->bpf, "ipftrace_main4");

  if ((error = libbpf_get_error(main1)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_program_by_title: %s\n", error_buf);
    return -1;
  }

  if (ipft->verbose <= IPFT_DEBUG_WARN) {
    orig_fn = libbpf_set_print(pr_suppress_warn);
  } else {
    orig_fn = NULL;
  }

  switch (si->skb_pos) {
    case 1:
      link = bpf_program__attach_kprobe(main1, false, sym);
      break;
    case 2:
      link = bpf_program__attach_kprobe(main2, false, sym);
      break;
    case 3:
      link = bpf_program__attach_kprobe(main3, false, sym);
      break;
    case 4:
      link = bpf_program__attach_kprobe(main4, false, sym);
      break;
    default:
      fprintf(stderr, "Invalid skb position\n");
      return -1;
  }

  if (libbpf_get_error(link) == 0) {
    ipft->astat.attached++;
  } else {
    ipft->astat.failed++;
  }

  printf(ATTACH_FMT, ipft->astat.total,
      ipft->astat.attached, ipft->astat.failed);

  if (orig_fn != NULL) {
    libbpf_set_print(orig_fn);
  }

  return 0;
}

static int debug_pr(enum libbpf_print_level level, const char *format,
             va_list args)
{
  return vfprintf(stderr, format, args);
}

static void
handle_event(void *ctx, int cpu, void *data, __u32 size)
{
  int error;
  struct ipft *ipft;
  struct ipft_trace *trace;

  ipft = (struct ipft *)ctx;
  trace = (struct ipft_trace *)data;

  error = ipft_trace_add(ipft->ts, trace);
  if (error != 0) {
    fprintf(stderr, "Failed to add trace: %s\n", strerror(error));
    exit(EXIT_FAILURE);
  }
}

static void
handle_lost(void *ctx, int cpu, __u64 cnt)
{
  fprintf(stderr, "%llu events lost\n", cnt);
}

static bool trace_finish = false;

static void
handle_sigint(int sig)
{
  trace_finish = true;
}

static void
do_trace(struct ipft *ipft)
{
  struct bpf_object *bpf;
  struct perf_buffer *pb;
  libbpf_print_fn_t orig_fn;
  struct ipft_ctrl_data cdata;
  struct perf_buffer_opts pb_opts;
  int error, ctrl_map_fd, events_fd;

  if (ipft->verbose <= IPFT_DEBUG_DEBUG) {
    orig_fn = libbpf_set_print(debug_pr);
  } else {
    orig_fn = NULL;
  }

  bpf = bpf_object__open_buffer(ipftrace_bpf_o,
      ipftrace_bpf_o_len, "ipftrace2");
  if ((error = libbpf_get_error(bpf)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__open_mem: %s\n", error_buf);
    return;
  }

  error = bpf_object__load(bpf);
  if (error != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__load: %s\n", error_buf);
    return;
  }

  ctrl_map_fd = bpf_object__find_map_fd_by_name(bpf, "ctrl_map");
  if (ctrl_map_fd < 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_map_by_name: %s\n", error_buf);
    return;
  }

  cdata.mark = ipft->topt->mark;
  cdata.mark_offset = ipft_symsdb_get_mark_offset(ipft->sdb);
  error = bpf_map_update_elem(ctrl_map_fd, &(int){0}, &cdata, BPF_ANY);
  if (error != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_map_update_elem: %s\n", error_buf);
    return;
  }

  if (orig_fn != NULL) {
    libbpf_set_print(orig_fn);
  }

  ipft->bpf = bpf;
  ipft->astat.total = ipft_symsdb_get_total(ipft->sdb);
  ipft->astat.attached = 0;
  ipft->astat.failed = 0;

  error = ipft_symsdb_foreach_syms(ipft->sdb, attach_kprobe, ipft);
  if (error != 0) {
    fprintf(stderr, "Failed to attach kprobe\n");
    return;
  }

  printf("\n");

  events_fd = bpf_object__find_map_fd_by_name(bpf, "events");
  if (events_fd < 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_map_by_name: %s\n", error_buf);
    return;
  }

  pb_opts.sample_cb = handle_event;
  pb_opts.lost_cb = handle_lost;
  pb_opts.ctx = ipft;

  signal(SIGINT, handle_sigint);

  pb = perf_buffer__new(events_fd, 64, &pb_opts);
  if ((error = libbpf_get_error(pb)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "perf_buffer__new: %s\n", error_buf);
    return;
  }

  while ((error = perf_buffer__poll(pb, 100)) >= 0) {
    if (trace_finish) {
      break;
    }
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
  struct ipft ipft;
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
