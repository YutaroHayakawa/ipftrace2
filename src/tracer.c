#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/types.h>

#include <gelf.h>
#include <libelf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipft.h"
#include "ipft_kprobe.bpf.o.h"
#include "ipft_kprobe_multi.bpf.o.h"
#include "ipft_ftrace.bpf.o.h"
#include "null_module.bpf.o.h"

struct ipft_tracer {
  struct bpf_object *bpf;
  struct ipft_regex *re;
  struct ipft_symsdb *sdb;
  struct ipft_tracer_opt *opt;
  struct ipft_output *out;
  struct ipft_script *script;
  struct perf_buffer *pb;
};

enum ipft_tracers
get_tracer_id_by_name(const char *name)
{
  if (strcmp(name, "function") == 0) {
    return IPFT_TRACER_FUNCTION;
  }

  if (strcmp(name, "function_graph") == 0) {
    return IPFT_TRACER_FUNCTION_GRAPH;
  }

  return IPFT_TRACER_UNSPEC;
}

const char *
get_tracer_name_by_id(enum ipft_tracers id)
{
  switch (id) {
  case IPFT_TRACER_FUNCTION:
    return "function";
  case IPFT_TRACER_FUNCTION_GRAPH:
    return "function_graph";
  default:
    return NULL;
  }
}

enum ipft_backends
get_backend_id_by_name(const char *name)
{
  if (strcmp(name, "kprobe") == 0) {
    return IPFT_BACKEND_KPROBE;
  }

  if (strcmp(name, "ftrace") == 0) {
    return IPFT_BACKEND_FTRACE;
  }

  if (strcmp(name, "kprobe-multi") == 0) {
    return IPFT_BACKEND_KPROBE_MULTI;
  }

  return IPFT_BACKEND_UNSPEC;
}

const char *
get_backend_name_by_id(enum ipft_backends id)
{
  switch (id) {
  case IPFT_BACKEND_KPROBE:
    return "kprobe";
  case IPFT_BACKEND_FTRACE:
    return "ftrace";
  case IPFT_BACKEND_KPROBE_MULTI:
    return "kprobe-multi";
  default:
    return NULL;
  }
}

enum ipft_backends
select_backend_for_tracer(enum ipft_tracers tracer)
{
  bool has_kprobe_multi = probe_kprobe_multi();

  if (tracer == IPFT_TRACER_FUNCTION) {
    if (has_kprobe_multi) {
      return IPFT_BACKEND_KPROBE_MULTI;
    } else {
      return IPFT_BACKEND_KPROBE;
    }
  }

  if (tracer == IPFT_TRACER_FUNCTION_GRAPH) {
    return IPFT_BACKEND_FTRACE;
  }

  return IPFT_BACKEND_UNSPEC;
}

int
get_max_args_for_backend(enum ipft_backends backend)
{
  switch (backend) {
  case IPFT_BACKEND_KPROBE:
  case IPFT_BACKEND_KPROBE_MULTI:
    return KPROBE_MAX_ARGS;
  case IPFT_BACKEND_FTRACE:
    return FTRACE_MAX_ARGS;
  default:
    // Shouldn't reach to here
    return 0;
  }
}

int
get_max_skb_pos_for_backend(enum ipft_backends backend)
{
  switch (backend) {
  case IPFT_BACKEND_KPROBE:
  case IPFT_BACKEND_KPROBE_MULTI:
    return KPROBE_MAX_SKB_POS;
  case IPFT_BACKEND_FTRACE:
    return FTRACE_MAX_SKB_POS;
  default:
    // Shouldn't reach to here
    return 0;
  }
}

static struct {
  size_t total;
  size_t succeeded;
  size_t failed;
  size_t filtered;
} attach_stat = {0};

static int
get_prog_by_pos(struct bpf_object *bpf, int pos,
                struct bpf_program **entry_prog, struct bpf_program **exit_prog)
{
  char name[32] = {0};
  struct bpf_program *prog;

  if (sprintf(name, "ipft_main%d", pos) < 0) {
    fprintf(stderr, "sprintf failed\n");
    return -1;
  }

  prog = bpf_object__find_program_by_name(bpf, name);
  if (prog == NULL) {
    fprintf(stderr, "bpf_object__find_program_by_name failed\n");
    return -1;
  }

  *entry_prog = prog;

  if (exit_prog == NULL) {
    return 0;
  }

  memset(name, 0, sizeof(name));

  if (sprintf(name, "ipft_main_return%d", pos) < 0) {
    fprintf(stderr, "sprintf failed\n");
    return -1;
  }

  prog = bpf_object__find_program_by_name(bpf, name);
  if (prog == NULL) {
    fprintf(stderr, "bpf_object__find_program_by_name failed\n");
    return -1;
  }

  *exit_prog = prog;

  return 0;
}

static int
attach_kprobe(struct ipft_tracer *t)
{
  int error;
  struct bpf_link *link;
  struct bpf_program *prog;
  struct ipft_sym *sym, **syms;

  for (int i = 0; i < KPROBE_MAX_SKB_POS; i++) {
    syms = symsdb_get_syms_by_pos(t->sdb, i);
    if (syms == NULL) {
      continue;
    }

    error = get_prog_by_pos(t->bpf, i, &prog, NULL);
    if (error == -1) {
      fprintf(stderr, "get_prog_by_pos failed\n");
      return -1;
    }

    for (int j = 0; j < symsdb_get_syms_total_by_pos(t->sdb, i); j++) {
      sym = syms[j];

      if (!regex_match(t->re, sym->symname)) {
        attach_stat.filtered++;
        goto out;
      }

      link = bpf_program__attach_kprobe(prog, false, sym->symname);
      if (link == NULL) {
        if (t->opt->verbose) {
          fprintf(stderr, "Attach kprobe failed for %s\n", sym->symname);
        }
        attach_stat.failed++;
        goto out;
      }

      attach_stat.succeeded++;

    out:
      fprintf(stderr,
              "\rAttaching program (total %zu, succeeded %zu, failed %zu, "
              "filtered: "
              "%zu)",
              attach_stat.total, attach_stat.succeeded, attach_stat.failed,
              attach_stat.filtered);
      fflush(stderr);
    }
  }

  return 0;
}

static int
attach_kprobe_multi(struct ipft_tracer *t)
{
  int error;
  uint64_t *addrs;
  struct bpf_link *link;
  struct bpf_program *prog;
  struct ipft_sym *sym, **syms;

  for (int i = 0; i < KPROBE_MAX_SKB_POS; i++) {
    syms = symsdb_get_syms_by_pos(t->sdb, i);
    if (syms == NULL) {
      continue;
    }

    error = get_prog_by_pos(t->bpf, i, &prog, NULL);
    if (error == -1) {
      fprintf(stderr, "get_prog_by_pos failed\n");
      return -1;
    }

    addrs =
        calloc(symsdb_get_syms_total_by_pos(t->sdb, i), sizeof(*addrs));
    if (addrs == NULL) {
      fprintf(stderr, "calloc failed\n");
      return -1;
    }

    size_t cur = 0;

    for (int j = 0; j < symsdb_get_syms_total_by_pos(t->sdb, i); j++) {
      sym = syms[j];

      if (!regex_match(t->re, sym->symname)) {
        attach_stat.filtered++;
        continue;
      }

      addrs[cur++] = sym->addr;
    }

    struct bpf_kprobe_multi_opts opts = {
        .sz = sizeof(opts),
        .addrs = addrs,
        .cnt = cur,
    };

    link = bpf_program__attach_kprobe_multi_opts(prog, NULL, &opts);

    error = libbpf_get_error(link);
    if (error != 0) {
      if (t->opt->verbose) {
        fprintf(stderr, "bpf_program__attach_kprobe_multi_opts failed: %s\n",
                libbpf_error_string(error));
      }
      attach_stat.failed += opts.cnt;
    } else {
      attach_stat.succeeded += opts.cnt;
    }

    fprintf(
        stderr,
        "\rAttaching program (total %zu, succeeded %zu, failed %zu, filtered: "
        "%zu)",
        attach_stat.total, attach_stat.succeeded, attach_stat.failed,
        attach_stat.filtered);
    fflush(stderr);
  }

  return 0;
}

static int
attach_ftrace(struct ipft_tracer *t)
{
  int error, btf_fd;
  int entry_fd, exit_fd;
  char log_buf[4096] = {0};
  int entry_tp_fd, exit_tp_fd;
  struct ipft_sym *sym, **syms;
  size_t entry_size, exit_size;
  struct bpf_program *entry_prog, *exit_prog;
  const struct bpf_insn *entry_insns, *exit_insns;

  btf_fd = bpf_object__btf_fd(t->bpf);
  if (btf_fd < 0) {
    fprintf(stderr, "bpf_object__btf_fd failed\n");
    return -1;
  }

  for (int i = 0; i < FTRACE_MAX_SKB_POS; i++) {
    syms = symsdb_get_syms_by_pos(t->sdb, i);
    if (syms == NULL) {
      continue;
    }

    error = get_prog_by_pos(t->bpf, i, &entry_prog, &exit_prog);
    if (error == -1) {
      fprintf(stderr, "get_prog_by_pos failed\n");
      return -1;
    }

    entry_insns = bpf_program__insns(entry_prog);
    exit_insns = bpf_program__insns(exit_prog);
    entry_size = bpf_program__insn_cnt(entry_prog);
    exit_size = bpf_program__insn_cnt(exit_prog);

    for (int j = 0; j < symsdb_get_syms_total_by_pos(t->sdb, i); j++) {
      sym = syms[j];

      if (!regex_match(t->re, sym->symname)) {
        attach_stat.filtered++;
        goto out;
      }

      struct bpf_prog_load_opts opts = {
          .sz = sizeof(opts),
          .prog_btf_fd = btf_fd,
          .attach_btf_id = sym->btf_id,
          .attach_btf_obj_fd = sym->btf_fd,
          .log_level = 4,
          .log_size = sizeof(log_buf),
          .log_buf = log_buf,
      };

      opts.expected_attach_type = BPF_TRACE_FENTRY;

      entry_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", entry_insns,
                               entry_size, &opts);
      if (error == -1) {
        if (t->opt->verbose) {
          fprintf(stderr, "bpf_prog_load for %s entry failed\n%s", sym->symname,
                  log_buf);
        }
        attach_stat.failed++;
        goto out;
      }

      opts.expected_attach_type = BPF_TRACE_FEXIT;

      exit_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", exit_insns,
                              exit_size, &opts);
      if (error == -1) {
        if (t->opt->verbose) {
          fprintf(stderr, "bpf_prog_load for %s exit failed\n%s", sym->symname,
                  log_buf);
        }
        attach_stat.failed++;
        goto out;
      }

      entry_tp_fd = bpf_raw_tracepoint_open(NULL, entry_fd);
      if (entry_tp_fd < 0) {
        if (t->opt->verbose) {
          fprintf(stderr, "bpf_raw_tracepoint_open for %s entry failed: %s\n",
                  sym->symname, libbpf_error_string(entry_tp_fd));
        }
        attach_stat.failed++;
        goto out;
      }

      exit_tp_fd = bpf_raw_tracepoint_open(NULL, exit_fd);
      if (exit_tp_fd < 0) {
        if (t->opt->verbose) {
          fprintf(stderr, "bpf_raw_tracepoint_open for %s exit failed: %s\n",
                  sym->symname, libbpf_error_string(entry_tp_fd));
        }
        attach_stat.failed++;
        goto out;
      }

      attach_stat.succeeded++;

    out:
      fprintf(stderr,
              "\rAttaching program (total %zu, succeeded %zu, failed %zu, "
              "filtered: "
              "%zu)",
              attach_stat.total, attach_stat.succeeded, attach_stat.failed,
              attach_stat.filtered);
      fflush(stderr);
    }
  }

  return 0;
}

static int
attach_all(struct ipft_tracer *t)
{
  int error;

  attach_stat.total = symsdb_get_syms_total(t->sdb);

  fprintf(stderr,
          "Attaching program (total %zu, succeeded 0, failed 0, filtered: 0)",
          attach_stat.total);

  switch (t->opt->backend) {
  case IPFT_BACKEND_KPROBE:
    error = attach_kprobe(t);
    if (error == -1) {
      return -1;
    }
    break;
  case IPFT_BACKEND_FTRACE:
    error = attach_ftrace(t);
    if (error == -1) {
      return -1;
    }
    break;
  case IPFT_BACKEND_KPROBE_MULTI:
    error = attach_kprobe_multi(t);
    if (error == -1) {
      return -1;
    }
    break;
  default:
    fprintf(stderr, "Unknown backend ID %d\n", t->opt->backend);
    return -1;
  }

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
    error = output_on_trace(t->out, (struct ipft_event *)s->data);
    if (error == -1) {
      return LIBBPF_PERF_EVENT_ERROR;
    }
    break;
  case PERF_RECORD_LOST:
    error = 0;
    break;
  default:
    fprintf(stderr, "BUG: Unknown event type %d\n", ehdr->type);
    return LIBBPF_PERF_EVENT_ERROR;
  }

  return LIBBPF_PERF_EVENT_CONT;
}

static int
perf_buffer_create(struct perf_buffer **pbp, struct ipft_tracer *t,
                   size_t perf_page_cnt, uint64_t perf_sample_period,
                   uint32_t perf_wakeup_events)
{
  struct perf_buffer *pb;

  struct perf_buffer_raw_opts pb_opts = {
      .sz = sizeof(pb_opts),
      .cpu_cnt = 0,
  };

  struct perf_event_attr pe_attr = {
      .type = PERF_TYPE_SOFTWARE,
      .config = PERF_COUNT_SW_BPF_OUTPUT,
      .sample_period = perf_sample_period,
      .sample_type = PERF_SAMPLE_RAW,
      .wakeup_events = perf_wakeup_events,
  };

  pb = perf_buffer__new_raw(bpf_object__find_map_fd_by_name(t->bpf, "events"),
                            perf_page_cnt, &pe_attr, trace_cb, t, &pb_opts);
  if (pb == NULL) {
    fprintf(stderr, "perf_buffer__new_raw failed\n");
    return -1;
  }

  *pbp = pb;

  return 0;
}

/*
 * We need to carefully make sure tmpfiles we make in below functions
 * are unlinked. Otherwise, we'll leak the tmpfiles in user's /tmp.
 */

static int
create_tmpfile_from_image(int *fdp, char **namep, uint8_t *image,
                          size_t image_size)
{
  int fd;
  char *name;

  name = strdup("/tmp/ipft_XXXXXX");
  if (name == NULL) {
    fprintf(stderr, "Failed to allocate memory for tmpfile name\n");
    return -1;
  }

  fd = mkstemp(name);
  if (fd == -1) {
    fprintf(stderr, "Failed to create tmpfile\n");
    return -1;
  }

  if (write(fd, image, image_size) == -1) {
    fprintf(stderr, "Failed to write image to tmpfile\n");
    goto err0;
  }

  *fdp = fd;
  *namep = name;

  return 0;

err0:
  close(fd);
  unlink(name);
  return -1;
}

static int
do_link(char **namep, uint8_t *target_image, size_t target_image_size,
        uint8_t *module_image, size_t module_image_size)
{
  char *name;
  struct bpf_linker *linker;
  char *target_name, *module_name;
  int error = -1, target_fd, module_fd;

  error = create_tmpfile_from_image(&target_fd, &target_name, target_image,
                                    target_image_size);
  if (error == -1) {
    fprintf(stderr, "create_tmpfile_from_image for target image failed\n");
    return -1;
  }

  error = create_tmpfile_from_image(&module_fd, &module_name, module_image,
                                    module_image_size);
  if (error == -1) {
    fprintf(stderr, "create_tmpfile_from_image for module image failed\n");
    goto err0;
  }

  struct bpf_linker_opts lopts = {.sz = sizeof(lopts)};

  name = tmpnam(NULL);

  linker = bpf_linker__new(name, &lopts);
  if (linker == NULL) {
    fprintf(stderr, "bpf_linker__create failed\n");
    goto err1;
  }

  struct bpf_linker_file_opts fopts = {.sz = sizeof(fopts)};

  error = bpf_linker__add_file(linker, target_name, &fopts);
  if (error == -1) {
    fprintf(stderr, "bpf_linker__add_file failed\n");
    goto err2;
  }

  error = bpf_linker__add_file(linker, module_name, &fopts);
  if (error == -1) {
    fprintf(stderr, "bpf_linker__add_file failed\n");
    goto err2;
  }

  error = bpf_linker__finalize(linker);
  if (error == -1) {
    fprintf(stderr, "bpf_linker__finalize failed\n");
    goto err2;
  }

  error = 0;
  *namep = name;

err2:
  bpf_linker__free(linker);
err1:
  close(module_fd);
  unlink(module_name);
err0:
  close(target_fd);
  unlink(target_name);
  return error;
}

static int
get_target_image(enum ipft_backends backend, uint8_t **imagep,
                 size_t *image_sizep)
{
  switch (backend) {
  case IPFT_BACKEND_KPROBE:
    *imagep = ipft_kprobe_bpf_o;
    *image_sizep = ipft_kprobe_bpf_o_len;
    break;
  case IPFT_BACKEND_FTRACE:
    *imagep = ipft_ftrace_bpf_o;
    *image_sizep = ipft_ftrace_bpf_o_len;
    break;
  case IPFT_BACKEND_KPROBE_MULTI:
    *imagep = ipft_kprobe_multi_bpf_o;
    *image_sizep = ipft_kprobe_multi_bpf_o_len;
    break;
  default:
    fprintf(stderr, "Unsupported backend ID %d\n", backend);
    return -1;
  }
  return 0;
}

static int
get_default_module_image(uint8_t **imagep, size_t *image_sizep)
{
  *imagep = null_module_bpf_o;
  *image_sizep = null_module_bpf_o_len;
  return 0;
}

static int
ftrace_set_init_target(struct bpf_object *bpf, struct ipft_tracer *t)
{
  int error;

  for (int i = 0; i < FTRACE_MAX_SKB_POS; i++) {
    struct ipft_sym *sym;
    struct bpf_program *entry_prog, *exit_prog;

    error = get_prog_by_pos(bpf, i, &entry_prog, &exit_prog);
    if (error == -1) {
      fprintf(stderr, "get_prog_by_pos failed\n");
      return -1;
    }

    if (symsdb_get_syms_total_by_pos(t->sdb, i) != 0) {
      sym = symsdb_get_syms_by_pos(t->sdb, i)[0];
    } else {
      bpf_program__set_autoload(entry_prog, false);
      bpf_program__set_autoload(exit_prog, false);
      continue;
    }

    error = bpf_program__set_attach_target(entry_prog, 0, sym->symname);
    if (error == -1) {
      fprintf(stderr, "bpf_program__set_attach_target failed\n");
      return -1;
    }

    error = bpf_program__set_attach_target(exit_prog, 0, sym->symname);
    if (error == -1) {
      fprintf(stderr, "bpf_program__set_attach_target failed\n");
      return -1;
    }
  }

  return 0;
}

static int
bpf_create(struct bpf_object **bpfp, uint32_t mark, uint32_t mask,
           enum ipft_backends backend, struct ipft_tracer *t)
{
  int error;
  char *name;
  struct bpf_object *bpf;
  struct ipft_trace_config conf;
  uint8_t *target_image, *module_image;
  size_t target_image_size, module_image_size;

  error = get_target_image(backend, &target_image, &target_image_size);
  if (error != 0) {
    fprintf(stderr, "get_target_image failed\n");
    return -1;
  }

  if (t->script != NULL) {
    error = script_get_program(t->script, &module_image, &module_image_size);
    if (error != 0) {
      fprintf(stderr, "script_get_program failed\n");
      return -1;
    }
  } else {
    error = get_default_module_image(&module_image, &module_image_size);
    if (error != 0) {
      fprintf(stderr, "get_default_module failed\n");
      return -1;
    }
  }

  error = do_link(&name, target_image, target_image_size, module_image,
                  module_image_size);
  if (error == -1) {
    fprintf(stderr, "do_link failed\n");
    return -1;
  }

  struct bpf_object_open_opts opts = {
      .sz = sizeof(opts),
      .object_name = "ipft",
  };

  bpf = bpf_object__open(name);
  if (bpf == NULL) {
    fprintf(stderr, "bpf_object__open failed\n");
    return -1;
  }

  unlink(name);

  if (backend == IPFT_BACKEND_FTRACE) {
    error = ftrace_set_init_target(bpf, t);
    if (error == -1) {
      fprintf(stderr, "ftrace_setup_prep failed\n");
      return -1;
    }
  }

  error = bpf_object__load(bpf);
  if (error == -1) {
    fprintf(stderr, "bpf_object__load failed\n");
    return -1;
  }

  conf.mark = mark;
  conf.mask = mask;

  error = bpf_map_update_elem(bpf_object__find_map_fd_by_name(bpf, "config"),
                              &(int){0}, &conf, 0);
  if (error == -1) {
    fprintf(stderr, "Cannot update config map\n");
    return -1;
  }

  *bpfp = bpf;

  return 0;
}

static bool end = false;

static void
handle_signal(__unused int signum)
{
  end = true;
  signal(SIGINT, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
}

static void *
handle_tcp_probe(void *arg)
{
  int error, lsock, csock;
  struct ipft_tracer_opt *opt = (struct ipft_tracer_opt *)arg;

  lsock = socket(AF_INET, SOCK_STREAM, 0);
  if (lsock == -1) {
    fprintf(stderr, "socket failed: %s\n", strerror(errno));
    pthread_exit(arg);
  }

  error = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
  if (error == -1) {
    fprintf(stderr, "setsockopt failed: %s\n", strerror(errno));
    pthread_exit(arg);
  }

  struct sockaddr_in laddr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = inet_addr("0.0.0.0"),
      .sin_port = htons(opt->probe_server_port),
  };

  error = bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr));
  if (error == -1) {
    fprintf(stderr, "bind failed: %s\n", strerror(errno));
    pthread_exit(arg);
  }

  error = listen(lsock, 100);
  if (error == -1) {
    fprintf(stderr, "listen failed: %s\n", strerror(errno));
    pthread_exit(arg);
  }

  while (!end) {
    struct sockaddr_in caddr = {};
    socklen_t caddr_len = sizeof(caddr);

    csock = accept(lsock, (struct sockaddr *)&caddr, &caddr_len);
    if (csock == -1) {
      fprintf(stderr, "accept failed: %s\n", strerror(errno));
      continue;
    }

    close(csock);
  }

  close(lsock);

  return arg;
}

int
tracer_run(struct ipft_tracer *t)
{
  int error;
  pthread_t thread;

  error = attach_all(t);
  if (error) {
    fprintf(stderr, "attach_all failed\n");
    return -1;
  }

  fprintf(stderr, "Trace ready!\n");

  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  if (t->opt->enable_probe_server) {
    error = pthread_create(&thread, NULL, handle_tcp_probe, (void *)t->opt);
    if (error == -1) {
      fprintf(stderr, "pthread_create failed: %s\n", strerror(errno));
      return -1;
    }

    error = pthread_detach(thread);
    if (error == -1) {
      fprintf(stderr, "pthread_detach failed: %s\n", strerror(errno));
      return -1;
    }
  }

  while (!end) {
    if ((error = perf_buffer__poll(t->pb, 1000)) < 0) {
      /* perf_buffer__poll cancelled with signal */
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

  if (t->script != NULL) {
    script_exec_fini(t->script);
  }

  return 0;
}

static bool
opt_validate(struct ipft_tracer_opt *opt)
{
  if (opt->backend == IPFT_BACKEND_UNSPEC) {
    fprintf(stderr, "Backend unspecified\n");
    return false;
  }

  if (opt->mark == 0 || opt->mask == 0) {
    fprintf(stderr, "mark/mask can't be zero\n");
    return false;
  }

  if (opt->tracer == IPFT_TRACER_UNSPEC) {
    fprintf(stderr, "Tracer unspecified\n");
    return false;
  }

  if (opt->perf_page_cnt == 0) {
    fprintf(stderr, "perf_page_count should be at least 1\n");
    return false;
  }

  return true;
}

int
tracer_create(struct ipft_tracer **tp, struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_tracer *t;

  if (!opt_validate(opt)) {
    fprintf(stderr, "Invalid option specified\n");
    return -1;
  }

  t = calloc(1, sizeof(*t));
  if (t == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  t->opt = opt;

  struct ipft_symsdb_opt sdb_opt = {
      .max_args = get_max_args_for_backend(opt->backend),
      .max_skb_pos = get_max_skb_pos_for_backend(opt->backend),
  };

  error = symsdb_create(&t->sdb, &sdb_opt);
  if (error != 0) {
    fprintf(stderr, "symsdb_create failed\n");
    return -1;
  }

  error = script_create(&t->script, opt->script);
  if (error == -1) {
    fprintf(stderr, "script_create failed\n");
    return -1;
  }

  error = bpf_create(&t->bpf, opt->mark, opt->mask, opt->backend, t);
  if (error == -1) {
    fprintf(stderr, "bpf_create failed\n");
    return -1;
  }

  error = regex_create(&t->re, opt->regex);
  if (error != 0) {
    fprintf(stderr, "regex_create failed\n");
    return -1;
  }

  error = output_create(&t->out, opt->output, t->sdb, t->script, opt->tracer);
  if (error != 0) {
    fprintf(stderr, "output_create failed\n");
    return -1;
  }

  error = perf_buffer_create(&t->pb, t, opt->perf_page_cnt,
                             opt->perf_sample_period, opt->perf_wakeup_events);
  if (error == -1) {
    fprintf(stderr, "perf_buffer_create failed\n");
    return -1;
  }

  *tp = t;

  return 0;
}
