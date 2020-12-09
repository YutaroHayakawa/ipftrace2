#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>

#include "ipftrace.h"
#include "ipft.bpf.skel.h"

struct ipft_tracer {
  struct ipft_bpf *bpf;
  struct ipft_regex *re;
  struct ipft_symsdb *sdb;
  struct ipft_output *out;
  struct ipft_tracedb *tdb;
  struct ipft_debuginfo *dinfo;
  struct ipft_traceable_set *tset;
  struct perf_buffer *pb;
};

static int
set_rlimit(struct ipft_symsdb *sdb)
{
  int error;
  size_t nfiles;
  struct rlimit lim;

  /*
   * Rough estimations for various file descriptors like eBPF
   * program, maps or perf events and kprobe events. This is
   * the "required" number of file descriptors.
   */
  nfiles = 32 + symsdb_get_sym2info_total(sdb);

  /*
   * Set locked memory limit to infinity
   */
  lim.rlim_cur = RLIM_INFINITY;
  lim.rlim_max = RLIM_INFINITY;
  error = setrlimit(RLIMIT_MEMLOCK, &lim);
  if (error == -1) {
    perror("setrlimit");
    return -1;
  }

  /*
   * Set file limit
   */
  error = getrlimit(RLIMIT_NOFILE, &lim);
  if (error == -1) {
    perror("getrlimit");
    return -1;
  }

  if (lim.rlim_cur < nfiles && lim.rlim_cur != RLIM_INFINITY) {
    lim.rlim_cur = nfiles;
  }

  if (lim.rlim_max != RLIM_INFINITY && lim.rlim_max < lim.rlim_cur) {
    lim.rlim_max = lim.rlim_cur;
  }

  error = setrlimit(RLIMIT_NOFILE, &lim);
  if (error == -1) {
    perror("setrlimit");
    return -1;
  }

  return 0;
}

static struct {
  size_t total;
  size_t succeeded;
  size_t failed;
  size_t filtered;
  size_t untraceable;
} attach_stat;

static int
attach_cb(const char *sym, struct ipft_syminfo *si, void *data)
{
  struct bpf_link *link;
  struct bpf_program *prog;
  struct ipft_tracer *t = (struct ipft_tracer *)data;

  if (!traceable_set_is_traceable(t->tset, sym)) {
    attach_stat.untraceable++;
    return 0;
  }

  if (!regex_match(t->re, sym)) {
    attach_stat.filtered++;
    return 0;
  }

  switch (si->skb_pos) {
  case 1:
    prog = t->bpf->progs.ipft_main1;
    break;
  case 2:
    prog = t->bpf->progs.ipft_main2;
    break;
  case 3:
    prog = t->bpf->progs.ipft_main3;
    break;
  case 4:
    prog = t->bpf->progs.ipft_main4;
    break;
  case 5:
    prog = t->bpf->progs.ipft_main5;
    break;
  default:
    fprintf(stderr, "Unsupported skb_pos %d\n", si->skb_pos);
    break;
  }

  link = bpf_program__attach_kprobe(prog, false, sym);
  if (link == NULL) {
    attach_stat.failed++;
    fprintf(stderr, "Attach kprobe failed for %s\n", sym);
    return -1;
  }

  attach_stat.succeeded++;

  fprintf(stderr,
          "\rAttaching program (total %zu, succeeded %zu, failed %zu filtered: "
          "%zu untraceable: %zu)",
          attach_stat.total, attach_stat.succeeded, attach_stat.failed,
          attach_stat.filtered, attach_stat.untraceable);
  fflush(stderr);

  return 0;
}

static int
attach_all(struct ipft_tracer *t)
{
  int error;
  attach_stat.total = symsdb_get_sym2info_total(t->sdb);
  error = symsdb_sym2info_foreach(t->sdb, attach_cb, t);
  fprintf(stderr, "\n");
  return error;
}

struct perf_sample_data {
  struct perf_event_header header;
  uint32_t size;
  uint8_t data[0];
};

static enum bpf_perf_event_ret
trace_cb(void *ctx, __unused int cpu, struct perf_event_header *ehdr)
{
  int error;
  struct ipft_tracer *t = (struct ipft_tracer *)ctx;
  struct perf_sample_data *s = (struct perf_sample_data *)ehdr;

  switch (ehdr->type) {
  case PERF_RECORD_SAMPLE:
    error = output_on_trace(t->out, (struct ipft_trace *)s->data);
    if (error == -1) {
      return LIBBPF_PERF_EVENT_ERROR;
    }
    break;
  case PERF_RECORD_LOST:
    break;
  default:
    return LIBBPF_PERF_EVENT_ERROR;
  }

  return LIBBPF_PERF_EVENT_CONT;
}

static int
perf_buffer_create(struct perf_buffer **pbp, struct ipft_tracer *t,
    size_t perf_page_cnt)
{
  struct perf_buffer *pb;
  struct perf_event_attr pe_attr = {0};
  struct perf_buffer_raw_opts pb_opts = {0};

  pe_attr.type = PERF_TYPE_SOFTWARE;
  pe_attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  pe_attr.sample_period = 1;
  pe_attr.sample_type = PERF_SAMPLE_RAW;
  pe_attr.wakeup_events = 1;

  pb_opts.attr = &pe_attr;
  pb_opts.event_cb = trace_cb;
  pb_opts.ctx = t;
  pb_opts.cpu_cnt = 0;

  pb = perf_buffer__new_raw(bpf_map__fd(t->bpf->maps.events),
      perf_page_cnt, &pb_opts);
  if (pb == NULL) {
    fprintf(stderr, "perf_buffer__new_raw failed\n");
    return -1;
  }

  *pbp = pb;

  return 0;
}

static int
bpf_create(struct ipft_bpf **bpfp, uint32_t mark, uint32_t mask)
{
  int error;
  struct ipft_bpf *bpf;

  bpf = ipft_bpf__open();
  if (bpf == NULL) {
    fprintf(stderr, "ipft_bpf__open failed\n");
    return -1;
  }

  bpf->rodata->target_mark = mark;
  bpf->rodata->target_mask = mask;

  error = ipft_bpf__load(bpf);
  if (error == -1) {
    fprintf(stderr, "ipft_bpf__load failed\n");
    return -1;
  }

  *bpfp = bpf;

  return 0;
}

static int
tracer_create(struct ipft_tracer **tp, struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_tracer *t;

  t = malloc(sizeof(*t));
  if (t == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  error = symsdb_create(&t->sdb);
  if (error != 0) {
    fprintf(stderr, "symsdb_create failed\n");
    return -1;
  }

  error = debuginfo_create(&t->dinfo);
  if (error != 0) {
    fprintf(stderr, "debuginfo_create failed\n");
    return -1;
  }

  error = debuginfo_fill_sym2info(t->dinfo, t->sdb);
  if (error != 0) {
    fprintf(stderr, "debuginfo_fill_sym2info failed\n");
    return -1;
  }

  error = kallsyms_fill_addr2sym(t->sdb);
  if (error != 0) {
    fprintf(stderr, "kallsyms_fill_addr2sym failed\n");
    return -1;
  }

  if (opt->set_rlimit) {
    error = set_rlimit(t->sdb);
    if (error == -1) {
      fprintf(stderr, "set_rlimit failed\n");
      return -1;
    }
  }

  error = bpf_create(&t->bpf, opt->mark, opt->mask);
  if (error == -1) {
    fprintf(stderr, "bpf_create failed\n");
    return -1;
  }

  error = regex_create(&t->re, opt->regex);
  if (error != 0) {
    fprintf(stderr, "regex_create failed\n");
    return -1;
  }

  error = traceable_set_create(&t->tset);
  if (error != 0) {
    fprintf(stderr, "tracable_set_create\n");
    return -1;
  }

  error = tracedb_create(&t->tdb);
  if (error != 0) {
    fprintf(stderr, "tracedb_create failed\n");
    return -1;
  }

  error = output_create(&t->out, opt->output_type, t->sdb);
  if (error != 0) {
    fprintf(stderr, "output_create failed\n");
    return -1;
  }

  error = perf_buffer_create(&t->pb, t, opt->perf_page_cnt);
  if (error == -1) {
    fprintf(stderr, "perf_buffer_create failed\n");
    return -1;
  }

  *tp = t;

  return 0;
}

static bool end = false;

static void
handle_sigint(__unused int signum)
{
  end = true;
  signal(SIGINT, SIG_DFL);
}

static int
do_trace(struct ipft_tracer *t)
{
  int error;

  signal(SIGINT, handle_sigint);

  while (!end) {
    if ((error = perf_buffer__poll(t->pb, 1000)) < 0) {
      /* perf_buffer__poll cancelled with SIGINT */
      if (end) {
        break;
      }
      return -1;
    }
  }

  error = output_post_trace(t->out);
  if (error == -1) {
    fprintf(stderr, "output_post_trace failed\n");
    return -1;
  }

  return 0;
}

int
tracer_run(struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_tracer *t;

  error = tracer_create(&t, opt);
  if (error == -1) {
    fprintf(stderr, "tracer_create failed\n");
    return -1;
  }

  error = attach_all(t);
  if (error) {
    fprintf(stderr, "attach_all failed\n");
    return -1;
  }

  fprintf(stderr, "Trace ready!\n");

  return do_trace(t);
}
