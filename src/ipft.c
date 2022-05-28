#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <linux/filter.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipft.h"

static struct option options[] = {
    {"backend", required_argument, 0, 'b'},
    {"help", no_argument, 0, 'h'},
    {"list", no_argument, 0, 'l'},
    {"mark", required_argument, 0, 'm'},
    {"output", required_argument, 0, 'o'},
    {"regex", required_argument, 0, 'r'},
    {"script", required_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"mask", required_argument, 0, '0'},
    {"perf-page-count", required_argument, 0, '0'},
    {"perf-sample-period", required_argument, 0, '0'},
    {"perf-wakeup-events", required_argument, 0, '0'},
    {"no-set-rlimit", no_argument, 0, '0'},
    {"enable-probe-server", no_argument, 0, '0'},
    {"probe-server-port", required_argument, 0, '0'},
    {NULL, 0, 0, 0},
};

static void
usage(void)
{
  fprintf(stderr,
          "Usage: ipft [OPTIONS]\n"
          "\n"
          "Options:\n"
          " -b, --backend            [BACKEND]       Specify trace backend\n"
          " -h, --help                               Show this text\n"
          " -l, --list                               List functions\n"
          " -m, --mark               [NUMBER]        Trace the packet marked "
          "with <mark> [required]\n"
          "   , --mask               [NUMBER]        Only match to the bits "
          "masked with given bitmask (default: 0xffffffff)\n"
          " -o, --output             [OUTPUT-FORMAT] Specify output format\n"
          " -r, --regex              [REGEX]         Filter the function to "
          "trace with regex\n"
          " -s, --script             [PATH]          Path to extension script\n"
          " -t, --tracer             [TRACER-TYPE]   Specify tracer type\n"
          " -v, --verbose                            Turn on debug message\n"
          "   , --perf-page-count    [NUMBER]        See page_count of "
          "perf_event_open(2) man page (default: 8)\n"
          "   , --perf-sample-period [NUMBER]        See sample_period of "
          "perf_event_open(2) man page (default: 1)\n"
          "   , --perf-wakeup-events [NUMBER]        See wakeup_events of "
          "perf_event_open(2) man page (default: 1)\n"
          "   , --no-set-rlimit                      Don't set rlimit\n"
          "   , --enable-probe-server                Enable probe server\n"
          "   , --probe-server-port                  Set probe server port\n"
          "\n"
          "BACKEND       := { kprobe, ftrace, kprobe-multi }"
          "OUTPUT-FORMAT := { aggregate, json }\n"
          "TRACER-TYPE   := { function, function_graph (experimental) }\n"
          "\n");
}

static void
opt_init(struct ipft_tracer_opt *opt)
{
  opt->backend = NULL;
  opt->mark = 0;
  opt->mask = 0xffffffff;
  opt->output_type = "aggregate";
  opt->perf_page_cnt = 8;
  opt->perf_sample_period = 1;
  opt->perf_wakeup_events = 1;
  opt->regex = NULL;
  opt->script = NULL;
  opt->tracer = "function";
  opt->verbose = false;
  opt->enable_probe_server = false;
  opt->probe_server_port = 13720;
}

static void
opt_dump(struct ipft_tracer_opt *opt)
{
  fprintf(stderr, "============   Options   ============\n");
  fprintf(stderr, "backend            : %s\n", opt->backend);
  fprintf(stderr, "mark               : 0x%x\n", opt->mark);
  fprintf(stderr, "mask               : 0x%x\n", opt->mask);
  fprintf(stderr, "regex              : %s\n", opt->regex);
  fprintf(stderr, "script             : %s\n", opt->script);
  fprintf(stderr, "tracer             : %s\n", opt->tracer);
  fprintf(stderr, "output_type        : %s\n", opt->output_type);
  fprintf(stderr, "perf_page_cnt      : %zu\n", opt->perf_page_cnt);
  fprintf(stderr, "perf_sample_period : %zu\n", opt->perf_sample_period);
  fprintf(stderr, "perf_wakeup_events : %u\n", opt->perf_wakeup_events);
  if (opt->enable_probe_server) {
    fprintf(stderr, "probe_server_port  : %u\n", opt->probe_server_port);
  }
  fprintf(stderr, "============ End Options ============\n");
}

static bool
opt_validate(struct ipft_tracer_opt *opt, bool list)
{
  if (!list && opt->mark == 0) {
    fprintf(stderr, "-m --mark is missing (or specified 0 which is invalid)\n");
    return false;
  }

  if (!list && opt->mask == 0) {
    fprintf(stderr, "Masking by 0 is not allowed\n");
    return false;
  }

  if (strcmp(opt->backend, "kprobe") != 0 &&
      strcmp(opt->backend, "ftrace") != 0 &&
      strcmp(opt->backend, "kprobe-multi") != 0) {
    fprintf(stderr, "Invalid trace backend %s\n", opt->backend);
    return false;
  }

  if (strcmp(opt->output_type, "aggregate") != 0 &&
      strcmp(opt->output_type, "json") != 0) {
    fprintf(stderr, "Invalid output format %s\n", opt->output_type);
    return false;
  }

  if (strcmp(opt->tracer, "function") != 0 &&
      strcmp(opt->tracer, "function_graph") != 0) {
    fprintf(stderr, "Invalid tracer type %s\n", opt->tracer);
    return false;
  }

  if (!list && opt->perf_page_cnt == 0) {
    fprintf(stderr, "Perf page count should be at least 1\n");
    return false;
  }

  return true;
}

static int
get_nr_open(unsigned int *nr_openp)
{
  unsigned int nr_open;

  FILE *f = fopen("/proc/sys/fs/nr_open", "r");
  if (f == NULL) {
    perror("Failed to open /proc/sys/fs/nr_open");
    return -1;
  }

  if (fscanf(f, "%u", &nr_open) != 1) {
    perror("Failed to read the value from /proc/sys/fs/nr_open");
    return -1;
  }

  fclose(f);

  *nr_openp = nr_open;

  return 0;
}

static int
do_set_rlimit(bool verbose)
{
  int error;
  struct rlimit lim;
  unsigned int nr_open;

  /*
   * Set locked memory limit to infinity
   */
  if (verbose) {
    fprintf(
        stderr,
        "Bumping RLIMIT_MEMLOCK (cur: RLIM_INFINITY, max: RLIM_INFINITY)\n");
  }

  lim.rlim_cur = RLIM_INFINITY;
  lim.rlim_max = RLIM_INFINITY;
  error = setrlimit(RLIMIT_MEMLOCK, &lim);
  if (error == -1) {
    perror("setrlimit");
    return -1;
  }

  /*
   * Get maximum possible value of open files
   */
  error = get_nr_open(&nr_open);
  if (error == -1) {
    fprintf(stderr, "get_nr_open failed\n");
    return -1;
  }

  /*
   * Set file limit
   */
  if (verbose) {
    fprintf(stderr, "Bumping RLIMIT_MEMLOCK (cur: %u, max: %u)\n", nr_open,
            nr_open);
  }

  lim.rlim_cur = nr_open;
  lim.rlim_max = nr_open;
  error = setrlimit(RLIMIT_NOFILE, &lim);
  if (error == -1) {
    fprintf(stderr,
            "setlimit failed (resource: RLIMIT_NOFILE, cur: %u, max: %u\n",
            nr_open, nr_open);
    return -1;
  }

  return 0;
}

static int
probe_kprobe_multi(void)
{
  int fd;

  struct bpf_insn insns[] = {
      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN(),
  };

  struct bpf_prog_load_opts popts = {
      .sz = sizeof(popts),
      .expected_attach_type = BPF_TRACE_KPROBE_MULTI,
  };

  /*
   * Actually, this load always succeeds regardless of the kernel support of
   * BPF_PROG_TYPE_KPROBE, because kernel doesn't check expected_attach_type
   * for BPF_PROG_TYPE_KPROBE. Thus, we need to attach program to probe support.
   */
  fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, NULL, "GPL", insns, 2, &popts);
  if (fd < 0) {
    return 0;
  }

  const char *syms[] = {"__kfree_skb"};

  struct bpf_link_create_opts lopts = {
      .sz = sizeof(lopts),
      .kprobe_multi =
          {
              .cnt = 1,
              .syms = syms,
          },
  };

  fd = bpf_link_create(fd, 0, BPF_TRACE_KPROBE_MULTI, &lopts);
  if (fd < 0) {
    char buf[1024] = {0};
    libbpf_strerror(fd, buf, 1024);
    printf("%s\n", buf);
    return 0;
  }

  return 1;
}

static int
probe_fexit(void)
{
  int fd;
  char buf[4096];

  struct bpf_insn insns[] = {
      BPF_MOV64_IMM(BPF_REG_0, 0),
      BPF_EXIT_INSN(),
  };

  struct bpf_prog_load_opts opts = {
      .sz = sizeof(opts),
      .log_buf = buf,
      .log_size = sizeof(buf),
      .log_level = 1,
      .expected_attach_type = BPF_TRACE_FEXIT,
      .attach_btf_id = 1,
  };

  fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, 2, &opts);
  if (fd >= 0) {
    close(fd);
    return 1;
  }

  if (strstr(buf, "attach_btf_id 1 is not a function")) {
    return 1;
  }

  return 0;
}

static int
select_trace_backend(const char *tracer, char **backendp)
{
  int has_kprobe = libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_KPROBE, NULL);
  bool has_kprobe_multi = probe_kprobe_multi();
  int has_fentry = libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, NULL);
  bool has_fexit = probe_fexit();

  if (strcmp(tracer, "function") == 0) {
    if (has_kprobe_multi) {
      *backendp = "kprobe-multi";
    } else if (has_kprobe) {
      *backendp = "kprobe";
    } else {
      fprintf(stderr, "No available backend for function tracer\n");
      return -1;
    }
  } else if (strcmp(tracer, "function_graph") == 0) {
    if (has_fentry && has_fexit) {
      *backendp = "ftrace";
    } else {
      fprintf(stderr, "No available backend for function_graph tracer\n");
      return -1;
    }
  } else {
    fprintf(stderr, "Unsupported tracer %s\n", tracer);
    return -1;
  }

  return 0;
}

static int
debug_print(__unused enum libbpf_print_level level, const char *fmt, va_list ap)
{
  return vfprintf(stderr, fmt, ap);
}

int
main(int argc, char **argv)
{
  int c, optind;
  int error = -1;
  const char *optname;
  struct ipft_tracer *t;
  struct ipft_tracer_opt opt;
  bool list = false;
  bool set_rlimit = true;

  opt_init(&opt);

  while ((c = getopt_long(argc, argv, "b:hlm:o:r:s:t:v", options, &optind)) !=
         -1) {
    switch (c) {
    case 'b':
      opt.backend = strdup(optarg);
      break;
    case 'l':
      list = true;
      break;
    case 'm':
      opt.mark = strtoul(optarg, NULL, 0);
      break;
    case 'o':
      opt.output_type = strdup(optarg);
      break;
    case 'r':
      opt.regex = strdup(optarg);
      break;
    case 's':
      opt.script = strdup(optarg);
      break;
    case 't':
      opt.tracer = strdup(optarg);
      break;
    case 'v':
      opt.verbose = true;
      break;
    case '0':
      optname = options[optind].name;

      if (strcmp(optname, "mask") == 0) {
        opt.mask = strtoul(optarg, NULL, 0);
        break;
      }

      if (strcmp(optname, "perf-page-count") == 0) {
        opt.perf_page_cnt = strtoull(optarg, NULL, 10);
        break;
      }

      if (strcmp(optname, "perf-sample-period") == 0) {
        opt.perf_sample_period = strtoull(optarg, NULL, 10);
        break;
      }

      if (strcmp(optname, "perf-wakeup-events") == 0) {
        opt.perf_wakeup_events = strtoul(optarg, NULL, 10);
        break;
      }

      if (strcmp(optname, "no-set-rlimit") == 0) {
        set_rlimit = false;
        break;
      }

      if (strcmp(optname, "enable-probe-server") == 0) {
        opt.enable_probe_server = true;
        break;
      }

      if (strcmp(optname, "probe-server-port") == 0) {
        opt.probe_server_port = atoi(optarg);
        break;
      }

      break;
    default:
      usage();
      goto end;
    }
  }

  if (set_rlimit) {
    error = do_set_rlimit(opt.verbose);
    if (error == -1) {
      fprintf(stderr, "do_set_rlimit failed\n");
      return -1;
    }
  }

  if (opt.backend == NULL) {
    error = select_trace_backend(opt.tracer, &opt.backend);
    if (error == -1) {
      fprintf(stderr, "select_trace_backend failed\n");
      return -1;
    }
  }

  if (!opt_validate(&opt, list)) {
    usage();
    goto end;
  }

  if (list) {
    error = list_functions(&opt);
    goto end;
  }

  if (opt.verbose) {
    /* Enable debug print for libbpf */
    libbpf_set_print(debug_print);
    /* Print out all options user provided */
    opt_dump(&opt);
  }

  error = tracer_create(&t, &opt);
  if (error == -1) {
    fprintf(stderr, "Failed to create tracer\n");
    goto end;
  }

  error = tracer_run(t);
  if (error == -1) {
    fprintf(stderr, "Trace failed with error\n");
    goto end;
  }

end:
  return error == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
