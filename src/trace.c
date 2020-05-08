#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/epoll.h>
#include <linux/bpf.h>
#include <sys/signalfd.h>
#include <linux/perf_event.h>

#include "ipftrace.h"

enum event_types {
  EVENT_TYPE_PERF_BUFFER,
  EVENT_TYPE_SIGNAL
};

struct trace_data {
  enum event_types type;
  int fd;
  struct trace_ctx *ctx;
};

struct perf_sample_data {
  struct perf_event_header header;
  uint32_t size;
  uint8_t data[0];
};

struct kprobe_events {
  int *fds;
  size_t cnt;
};

struct attach_ctx {
  size_t total;
  size_t success;
  size_t fail;
  struct kprobe_events *ke;
  struct ipft_bpf_prog *prog;
};

struct trace_ctx {
  size_t nsamples;
  size_t nlost;
  struct ipft_symsdb *sdb;
  struct ipft_tracedb *tdb;
  struct ipft_script *script;
  struct ipft_perf_buffer *pb;
  struct ipft_bpf_prog *prog;
};

static int
debuginfo_create(const char *type, struct ipft_debuginfo **dinfop)
{
  if (strcmp(type, "dwarf") == 0) {
    return dwarf_debuginfo_create(dinfop);
  } else if (strcmp(type, "btf") == 0) {
    return btf_debuginfo_create(dinfop);
  } else {
    fprintf(stderr, "Unsupported debug info type %s\n", type);
    return -1;
  }
}

static int
load_progs(struct ipft_bpf_prog **progp, struct ipft_script *script,
    struct ipft_debuginfo *dinfo, struct ipft_perf_buffer *pb, uint32_t mark)
{
  int error = 0;
  size_t offset;
  uint32_t mod_cnt;
  struct bpf_insn *mod;

  error = script_exec_emit(script, &mod, &mod_cnt);
  if (error == -1) {
    fprintf(stderr, "ipft_script_exec_emit failed\n");
    return -1;
  }

  error = debuginfo_offsetof(dinfo, "sk_buff", "mark", &offset);
  if (error == -1) {
    fprintf(stderr, "debuginfo_offsetof failed\n");
    goto err0;
  }

  if (offset >= UINT32_MAX) {
    fprintf(stderr, "Offset of sk_buff is too large\n");
    goto err0;
  }

  error = bpf_prog_load(progp, mark, (uint32_t)offset, mod, mod_cnt);
  if (error == -1) {
    fprintf(stderr, "bpf_prog_load failed\n");
    goto err0;
  }

  error = bpf_prog_set_perf_fd(*progp, perf_buffer_get_fd(pb));
  if (error == -1) {
    fprintf(stderr, "bpf_prog_set_perf_fd failed\n");
    goto err0;
  }

err0:
  free(mod);
  return error;
}

static void
unload_progs(struct ipft_bpf_prog *prog)
{
  bpf_prog_unload(prog);
}

static int
kprobe_events_create(struct kprobe_events **kep, size_t cnt)
{
  struct kprobe_events *ke;

  ke = calloc(1, sizeof(*ke));
  if (ke == NULL) {
    perror("calloc");
    return -1;
  }

  ke->fds = calloc(cnt, sizeof(int));
  if (ke->fds == NULL) {
    perror("calloc");
    goto err0;
  }

  for (size_t i = 0; i < cnt; i++) {
    ke->fds[i] = -1;
  }

  ke->cnt = cnt;

  *kep = ke;

  return 0;

err0:
  free(ke);
  return -1;
}

static void
kprobe_events_destroy(struct kprobe_events *ke)
{
  free(ke->fds);
  free(ke);
}

static int
attach_prog(const char *name, struct ipft_syminfo *si, void *args)
{
  int pfd, prog_fd;
  struct attach_ctx *ctx;

  ctx = (struct attach_ctx *)args;

  prog_fd = bpf_prog_get(ctx->prog, si->skb_pos);

  pfd = perf_event_attach_kprobe(name, prog_fd);
  if (pfd > 0) {
    ctx->success++;
  } else {
    ctx->fail++;
  }

  ctx->ke->fds[ctx->success + ctx->fail - 1] = pfd;

  fprintf(stderr, "Attaching program (total %zu, success %zu, fail %zu)\r",
      ctx->total, ctx->success, ctx->fail);
  fflush(stderr);

  return 0;
}

static int
attach_progs(struct kprobe_events *ke, struct ipft_symsdb *sdb,
    struct ipft_bpf_prog *prog)
{
  int error;
  struct attach_ctx ctx = {};

  ctx.total = symsdb_get_sym2info_total(sdb);
  ctx.prog = prog;
  ctx.ke = ke;

  error = symsdb_sym2info_foreach(sdb, attach_prog, &ctx);
  if (error == -1) {
    fprintf(stderr, "symsdb_sym2info_foreach faild\n");
    return -1;
  }

  fprintf(stderr, "\n");

  return 0;
}

static void
detach_progs(struct kprobe_events *ke)
{
  for (size_t i = 0; i < ke->cnt; i++) {
    if (ke->fds[i] == -1) {
      continue;
    }
    close(ke->fds[i]);
  }
}

static int
register_trace_event(struct trace_data **datap, int epfd,
    struct trace_ctx *ctx)
{
  int error, pfd;
  struct epoll_event ev;
  struct trace_data *data;

  data = calloc(1, sizeof(*data));
  if (data == NULL) {
    perror("calloc");
    return -1;
  }

  pfd = perf_buffer_get_fd(ctx->pb);

  data->type = EVENT_TYPE_PERF_BUFFER;
  data->fd = pfd;
  data->ctx = ctx;

  ev.events = EPOLLIN;
  ev.data.ptr = data;

  error = epoll_ctl(epfd, EPOLL_CTL_ADD, pfd, &ev);
  if (error == -1) {
    perror("epoll_ctl");
    goto err0;
  }

  *datap = data;

  return 0;

err0:
  free(data);
  return -1;
}

static int
register_signal_event(struct trace_data **datap, int epfd,
    struct trace_ctx *ctx)
{
  int error, sigfd;
  sigset_t sigmask;
  struct epoll_event ev;
  struct trace_data *data;

  sigemptyset(&sigmask);
  sigaddset(&sigmask, SIGINT);
  sigaddset(&sigmask, SIGTERM);
  sigaddset(&sigmask, SIGCHLD);
  sigprocmask(SIG_BLOCK, &sigmask, NULL);

  sigfd = signalfd(-1, &sigmask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sigfd == -1) {
    perror("signalfd");
    return -1;
  }

  data = calloc(1, sizeof(*data));
  if (data == NULL) {
    perror("calloc");
    goto err0;
  }

  data->type = EVENT_TYPE_SIGNAL;
  data->fd = sigfd;
  data->ctx = ctx;

  ev.events = EPOLLIN;
  ev.data.ptr = data;

  error = epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev);
  if (error == -1) {
    perror("epoll_ctl");
    goto err1;
  }

  *datap = data;

  return 0;

err1:
  free(data);
err0:
  close(sigfd);
  return -1;
}

static void
unregister_event(struct trace_data *data, int epfd)
{
  int error;

  error = epoll_ctl(epfd, EPOLL_CTL_DEL, data->fd, NULL);
  assert(error == 0);

  close(data->fd);
  free(data);
}

static char *
dump_trace(uint8_t *data, size_t size, void *arg)
{
  struct trace_ctx *ctx;
  ctx = (struct trace_ctx *)arg;
  return script_exec_dump(ctx->script, data, size);
}

static int
store_trace(struct ipft_tracedb *tdb, uint8_t *data, uint32_t size)
{
  int error;
  struct ipft_trace *t;

  t = calloc(1, size);
  if (t == NULL) {
    perror("calloc");
    return -1;
  }

  memcpy(t, data, size);

  error = tracedb_put_trace(tdb, t);
  if (error == -1) {
    fprintf(stderr, "tracedb_put_trace failed\n");
    goto err0;
  }

  return 0;

err0:
  free(t);
  return -1;
}

static int
handle_perf_buffer_event(struct perf_event_header *ehdr, void *data)
{
  int error;
  struct perf_sample_data *s;
  struct trace_ctx *ctx = data;

  switch (ehdr->type) {
  case PERF_RECORD_SAMPLE:
    ctx->nsamples++;
    s = (struct perf_sample_data *)ehdr;
    error = store_trace(ctx->tdb, s->data, s->size);
    break;
  case PERF_RECORD_LOST:
    ctx->nlost++;
    error = 0;
    break;
  default:
    fprintf(stderr, "Unknown event type %d\n", ehdr->type);
    return -1;
  }

  fprintf(stderr, "Samples: %zu Lost: %zu\r", ctx->nsamples, ctx->nlost);
  fflush(stderr);

  return error;
}

static void
do_trace(struct trace_ctx *ctx)
{
  int error, nfds, epfd;
  struct epoll_event events[2];
  struct trace_data *data, *trace_data, *sig_data;

  epfd = epoll_create(1);
  if (epfd == -1) {
    perror("epoll_create");
    return;
  }

  error = register_trace_event(&trace_data, epfd, ctx);
  if (error == -1) {
    fprintf(stderr, "register_trace_event failed\n");
    goto err0;
  }

  error = register_signal_event(&sig_data, epfd, ctx);
  if (error == -1) {
    fprintf(stderr, "register_signal_event failed\n");
    goto err1;
  }

  fprintf(stderr, "Trace ready!\n");

  while (true) {
    nfds = epoll_wait(epfd, events, 2, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      goto err2;
    }

    for (int i = 0; i < nfds; i++) {
      data = (struct trace_data *)(events[i].data.ptr);
      switch (data->type) {
      case EVENT_TYPE_PERF_BUFFER:
        error = perf_event_process_mmap_page(ctx->pb,
            handle_perf_buffer_event, ctx);
        if (error == -1) {
          fprintf(stderr, "handle_perf_buffer_event failed\n");
          goto err2;
        }
        break;
      case EVENT_TYPE_SIGNAL:
        /* Insert line break since we have statistics displayed with \r */
        fprintf(stderr, "\nTrace done!\n");
        goto end;
      default:
        printf("Got unknown event\n");
        assert(false);
      }
    }
  }

end:
  tracedb_dump(ctx->tdb, ctx->sdb, dump_trace, ctx);
err2:
  unregister_event(sig_data, epfd);
err1:
  unregister_event(trace_data, epfd);
err0:
  close(epfd);
  return;
}

int
tracer_run(struct ipft_tracer_opt *opt)
{
  int error;
  struct trace_ctx ctx;
  struct ipft_symsdb *sdb;
  struct ipft_tracedb *tdb;
  struct kprobe_events *ke;
  struct ipft_script *script;
  struct ipft_bpf_prog *prog;
  struct ipft_perf_buffer *pb;
  struct ipft_debuginfo *dinfo;

  error = symsdb_create(&sdb);
  if (error == -1) {
    fprintf(stderr, "symsdb_create failed\n");
    return -1;
  }

  error = tracedb_create(&tdb);
  if (error == -1) {
    fprintf(stderr, "tracedb_create failed\n");
    goto err0;
  }

  error = debuginfo_create(opt->debug_info_type, &dinfo);
  if (error == -1) {
    fprintf(stderr, "debuginfo_create failed\n");
    goto err1;
  }

  error = debuginfo_fill_sym2info(dinfo, sdb);
  if (error == -1) {
    fprintf(stderr, "debuginfo_fill_sym2info failed\n");
    goto err2;
  }

  error = kallsyms_fill_addr2sym(sdb);
  if (error == -1) {
    fprintf(stderr, "kallsyms_fill_addr2sym failed\n");
    goto err2;
  }

  error = script_create(&script, dinfo, opt->script_path);
  if (error == -1) {
    fprintf(stderr, "script_create failed\n");
    goto err2;
  }

  error = perf_buffer_create(&pb, opt->perf_page_cnt);
  if (error == -1) {
    fprintf(stderr, "perf_buffer_create failed\n");
    goto err3;
  }

  error = load_progs(&prog, script, dinfo, pb, opt->mark);
  if (error == -1) {
    fprintf(stderr, "load_progs failed\n");
    goto err4;
  }

  error = kprobe_events_create(&ke, symsdb_get_sym2info_total(sdb));
  if (error == -1) {
    fprintf(stderr, "kprobe_events_create failed\n");
    goto err5;
  }

  error = attach_progs(ke, sdb, prog);
  if (error == -1) {
    fprintf(stderr, "attach_progs failed\n");
    goto err6;
  }

  ctx.nsamples = 0;
  ctx.nlost = 0;
  ctx.sdb = sdb;
  ctx.tdb = tdb;
  ctx.script = script;
  ctx.pb = pb;
  ctx.sdb = sdb;
  ctx.prog = prog;

  do_trace(&ctx);

  detach_progs(ke);
err6:
  kprobe_events_destroy(ke);
err5:
  unload_progs(prog);
err4:
  perf_buffer_destroy(pb);
err3:
  script_destroy(script);
err2:
  debuginfo_destroy(dinfo);
err1:
  tracedb_destroy(tdb);
err0:
  symsdb_destroy(sdb);
  return error;
}
