#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <gelf.h>
#include <libelf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipft.h"
#include "ipft.bpf.o.h"
#include "null_module.bpf.o.h"

struct ipft_tracer {
  struct bpf_object *bpf;
  struct ipft_regex *re;
  struct ipft_symsdb *sdb;
  struct ipft_output *out;
  struct ipft_script *script;
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
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main1");
    break;
  case 2:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main2");
    break;
  case 3:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main3");
    break;
  case 4:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main4");
    break;
  case 5:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main5");
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

  fprintf(
      stderr,
      "\rAttaching program (total %zu, succeeded %zu, failed %zu, filtered: "
      "%zu, untraceable: %zu)",
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
  struct perf_event_attr pe_attr = {0};
  struct perf_buffer_raw_opts pb_opts = {0};

  pe_attr.type = PERF_TYPE_SOFTWARE;
  pe_attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  pe_attr.sample_period = perf_sample_period;
  pe_attr.sample_type = PERF_SAMPLE_RAW;
  pe_attr.wakeup_events = perf_wakeup_events;

  pb_opts.attr = &pe_attr;
  pb_opts.event_cb = trace_cb;
  pb_opts.ctx = t;
  pb_opts.cpu_cnt = 0;

  pb = perf_buffer__new_raw(bpf_object__find_map_fd_by_name(t->bpf, "events"),
                            perf_page_cnt, &pb_opts);
  if (pb == NULL) {
    fprintf(stderr, "perf_buffer__new_raw failed\n");
    return -1;
  }

  *pbp = pb;

  return 0;
}

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
    return -1;
  }

  *fdp = fd;
  *namep = name;

  return 0;
}

static int
do_link(char **namep, uint8_t *target_image, size_t target_image_size,
        uint8_t *module_image, size_t module_image_size)
{
  char *name;
  struct bpf_linker *linker;
  int error, target_fd, module_fd;
  char *target_name, *module_name;

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
    return -1;
  }

  struct bpf_linker_opts lopts = {.sz = sizeof(lopts)};

  name = tmpnam(NULL);

  linker = bpf_linker__new(name, &lopts);
  if (linker == NULL) {
    fprintf(stderr, "bpf_linker__create failed\n");
    return -1;
  }

  struct bpf_linker_file_opts fopts = {.sz = sizeof(fopts)};

  error = bpf_linker__add_file(linker, target_name, &fopts);
  if (error == -1) {
    fprintf(stderr, "bpf_linker__add_file failed\n");
    return -1;
  }

  error = bpf_linker__add_file(linker, module_name, &fopts);
  if (error == -1) {
    fprintf(stderr, "bpf_linker__add_file failed\n");
    return -1;
  }

  error = bpf_linker__finalize(linker);
  if (error == -1) {
    fprintf(stderr, "bpf_linker__finalize failed\n");
    return -1;
  }

  bpf_linker__free(linker);

  close(target_fd);
  close(module_fd);
  unlink(target_name);
  unlink(module_name);
  free(target_name);
  free(module_name);

  *namep = name;

  return 0;
}

static int
get_target_image(uint8_t **imagep, size_t *image_sizep)
{
  *imagep = ipft_bpf_o;
  *image_sizep = ipft_bpf_o_len;
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
bpf_create(struct bpf_object **bpfp, uint32_t mark, uint32_t mask,
           struct ipft_script *script)
{
  int error;
  char *name;
  struct bpf_object *bpf;
  struct ipft_trace_config conf;
  uint8_t *target_image, *module_image;
  size_t target_image_size, module_image_size;

  error = get_target_image(&target_image, &target_image_size);
  if (error != 0) {
    fprintf(stderr, "get_target_image failed\n");
    return -1;
  }

  if (script != NULL) {
    error = script_exec_emit(script, &module_image, &module_image_size);
    if (error != 0) {
      fprintf(stderr, "script_exec_emit failed\n");
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

static int
tracer_create(struct ipft_tracer **tp, struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_tracer *t;

  t = calloc(1, sizeof(*t));
  if (t == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  error = symsdb_create(&t->sdb);
  if (error != 0) {
    fprintf(stderr, "symsdb_create failed\n");
    return -1;
  }

  error = kernel_btf_fill_sym2info(t->sdb);
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

  error = script_create(&t->script, opt->script);
  if (error == -1) {
    fprintf(stderr, "script_create failed\n");
    return -1;
  }

  error = bpf_create(&t->bpf, opt->mark, opt->mask, t->script);
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

  error = output_create(&t->out, opt->output_type, t->sdb, t->script);
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

  if (t->script != NULL) {
    script_exec_fini(t->script);
  }

  return 0;
}

static int
debug_print(__unused enum libbpf_print_level level, const char *fmt, va_list ap)
{
  return vfprintf(stderr, fmt, ap);
}

int
tracer_run(struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_tracer *t;

  if (opt->verbose) {
    libbpf_set_print(debug_print);
  }

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
