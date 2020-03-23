#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipftrace.h"
#include "ipftrace.elf.h"

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

struct trace_ctx {
  struct ipft_tracedb *tdb;
};

#define ERROR_BUF_SIZE 256

static bool trace_finish = false;
static char error_buf[ERROR_BUF_SIZE] = {};

static int pr_suppress_warn(enum libbpf_print_level level,
    const char *format, va_list args) {
  if (level == LIBBPF_WARN) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

static void
on_sigint(__unused int sig)
{
  trace_finish = true;
}

static void
on_event(void *_ctx, __unused int cpu, void *data, __unused __u32 size)
{
  int error;
  struct ipft_trace *trace;
  struct trace_ctx *ctx;

  ctx = (struct trace_ctx *)_ctx;
  trace = (struct ipft_trace *)data;

  error = tracedb_put_trace(ctx->tdb, trace);
  if (error == -1) {
    fprintf(stderr, "Failed to add trace: %s\n", strerror(error));
  }

  printf("Captured %zu sk_buffs\r", tracedb_get_total(ctx->tdb));
}

static void
on_lost(__unused void *ctx, __unused int cpu, __u64 cnt)
{
  fprintf(stderr, "%llu events lost\n", cnt);
}

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

  printf("Attaching %zu probes (Attached: %zu Failed: %zu)\r",
      ctx->total, ctx->attached, ctx->failed);

  if (orig_fn != NULL) {
    libbpf_set_print(orig_fn);
  }

  return 0;
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

static int
attach_probes(struct bpf_object *bpf, struct ipft_symsdb *sdb, int verbose)
{
  int error;
  struct attach_ctx ctx;

  ctx.verbose = verbose;
  ctx.bpf = bpf;
  ctx.total = symsdb_get_sym2info_total(sdb);
  ctx.attached = 0;
  ctx.failed = 0;

  ctx.main1 = bpf_object__find_program_by_name(bpf, "ipftrace_main1");
  ctx.main2 = bpf_object__find_program_by_name(bpf, "ipftrace_main2");
  ctx.main3 = bpf_object__find_program_by_name(bpf, "ipftrace_main3");
  ctx.main4 = bpf_object__find_program_by_name(bpf, "ipftrace_main4");

  if ((error = libbpf_get_error(ctx.main1)) != 0 ||
      (error = libbpf_get_error(ctx.main2)) != 0 ||
      (error = libbpf_get_error(ctx.main3)) != 0 ||
      (error = libbpf_get_error(ctx.main4)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_program_by_title: %s\n", error_buf);
    return -1;
  }

  error = symsdb_sym2info_foreach(sdb, attach_kprobe, &ctx);
  if (error != 0) {
    fprintf(stderr, "Failed to attach kprobe\n");
    return -1;
  }

  printf("\n");

  return 0;
}

static int
run_trace(struct bpf_object *bpf, struct ipft_tracedb *tdb)
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

  ctx.tdb = tdb;

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

  printf("\n");

  return 0;
}

static int
debuginfo_create(struct ipft_debuginfo **dinfo, struct ipft_opt *opt)
{
  if (strcmp(opt->debug_format, "dwarf") == 0) {
    return dwarf_debuginfo_create(dinfo);
  }

  if (strcmp(opt->debug_format, "btf") == 0) {
    return btf_debuginfo_create(dinfo);
  }

  return -1;
}

void
do_trace(struct ipft_opt *opt)
{
  int error;
  struct bpf_object *bpf;
  struct ipft_symsdb *sdb;
  struct ipft_tracedb *tdb;
  struct ipft_debuginfo *dinfo;

  error = symsdb_create(&sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to create symsdb\n");
    return;
  }

  error = tracedb_create(&tdb);
  if (error == -1) {
    fprintf(stderr, "Failed to create tracedb\n");
    goto err0;
  }

  error = debuginfo_create(&dinfo, opt);
  if (error == -1) {
    fprintf(stderr, "Failed to create debuginfo\n");
    goto err1;
  }

  error = debuginfo_fill_sym2info(dinfo, sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to fill sym2info\n");
    goto err2;
  }

  error = kallsyms_fill_addr2sym(sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to fill addr2sym\n");
    goto err2;
  }

  bpf = bpf_object_open_and_load(ipftrace_bpf_o,
      ipftrace_bpf_o_len, "ipftrace2");
  if (bpf == NULL) {
    fprintf(stderr, "Failed to open and load BPF object\n");
    goto err2;
  }

  error = set_ctrl_data(bpf, opt->mark,
      symsdb_get_mark_offset(sdb));
  if (error == -1) {
    fprintf(stderr, "Failed to set BPF control data\n");
    goto err3;
  }

  error = attach_probes(bpf, sdb, opt->verbose);
  if (error == -1) {
    fprintf(stderr, "Failed to attach probes\n");
    goto err3;
  }

  error = run_trace(bpf, tdb);
  if (error == -1) {
    fprintf(stderr, "Error occured while running the trace\n");
    goto err3;
  }

  tracedb_dump(tdb, sdb, stdout);

err3:
  bpf_object__close(bpf);
err2:
  debuginfo_destroy(dinfo);
err1:
  tracedb_destroy(tdb);
err0:
  symsdb_destroy(sdb);
  return;
}
