#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipftrace.h"
#include <ipftrace.elf.h>

#define ERROR_BUF_SIZE 256

static char error_buf[ERROR_BUF_SIZE] = {};

static int pr_suppress_warn(enum libbpf_print_level level,
    const char *format, va_list args) {
  if (level == LIBBPF_WARN) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

struct ipft_attach_ctx {
  struct bpf_object *bpf;
  size_t attached;
  size_t failed;
  size_t total;
};

#define ATTACH_FMT "Attaching %zu probes (Attached: %zu Failed: %zu)\r"

static int
attach_kprobe(const char *sym, struct ipft_syminfo *si, void *arg)
{
  int error;
  struct bpf_link *link;
  libbpf_print_fn_t orig_fn;
  struct ipft_attach_ctx *ctx;
  struct bpf_program *main1, *main2, *main3, *main4;

  ctx = (struct ipft_attach_ctx *)arg;

  main1 = bpf_object__find_program_by_name(ctx->bpf, "ipftrace_main1");
  main2 = bpf_object__find_program_by_name(ctx->bpf, "ipftrace_main2");
  main3 = bpf_object__find_program_by_name(ctx->bpf, "ipftrace_main3");
  main4 = bpf_object__find_program_by_name(ctx->bpf, "ipftrace_main4");
  if ((error = libbpf_get_error(main1)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_program_by_title: %s\n", error_buf);
    return -1;
  }

  orig_fn = libbpf_set_print(pr_suppress_warn);

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
    ctx->attached++;
  } else {
    ctx->failed++;
  }

  printf(ATTACH_FMT, ctx->total, ctx->attached, ctx->failed);

  libbpf_set_print(orig_fn);

  return 0;
}

static int debug_pr(enum libbpf_print_level level, const char *format,
             va_list args)
{
  return vfprintf(stderr, format, args);
}

static void
do_trace(struct ipft *ipft)
{
  int error, ctrl_map_fd;
  struct bpf_object *bpf;
  struct ipft_ctrl_data cdata;
  struct ipft_attach_ctx attach_ctx;

  libbpf_set_print(debug_pr);

  bpf = bpf_object__open_buffer(obj_ipftrace_bpf_o,
      obj_ipftrace_bpf_o_len, "ipftrace2");
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

  attach_ctx.bpf = bpf;
  attach_ctx.total = 0;
  attach_ctx.attached = 0;
  attach_ctx.failed = 0;

  error = ipft_symsdb_foreach_syms(ipft->sdb, attach_kprobe, &attach_ctx);
  if (error != 0) {
    fprintf(stderr, "Failed to attach kprobe\n");
    return;
  }

  printf("\n");

  bpf_object__close(bpf);
}

static struct option options[] = {
  { "--mark",   required_argument, 0, 'm' },
  { "--format", required_argument, 0, 'f' }
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
  int error, opt, optind;
  struct ipft ipft;
  struct ipft_symsdb *sdb;
  struct ipft_trace_store *ts;
  struct ipft_trace_opt topt = {};
  struct ipft_symsdb_opt sopt = {};

  while ((opt = getopt_long(argc, argv, "m:f:",
          options, &optind)) != -1) {
    switch (opt) {
    case 'm':
      topt.mark = strtoul(optarg, NULL, 16);
      break;
    case 'f':
      sopt.format = strdup(optarg);
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
