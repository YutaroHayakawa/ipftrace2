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

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipft.h"

bool verbose = false;

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
  INFO("Usage: ipft [OPTIONS]\n"
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
       "BACKEND       := { kprobe, ftrace, kprobe-multi }\n"
       "OUTPUT-FORMAT := { aggregate, json }\n"
       "TRACER-TYPE   := { function, function_graph (experimental) }\n"
       "\n");
}

static void
opt_init(struct ipft_tracer_opt *opt)
{
  opt->backend = IPFT_BACKEND_UNSPEC;
  opt->mark = 0;
  opt->mask = 0xffffffff;
  opt->output = IPFT_OUTPUT_AGGREGATE;
  opt->perf_page_cnt = 8;
  opt->perf_sample_period = 1;
  opt->perf_wakeup_events = 1;
  opt->regex = NULL;
  opt->script = NULL;
  opt->tracer = IPFT_TRACER_FUNCTION;
  opt->enable_probe_server = false;
  opt->probe_server_port = 13720;
}

static void
opt_dump(struct ipft_tracer_opt *opt)
{
  INFO("============   Options   ============\n");
  INFO("backend            : %s\n", get_backend_name_by_id(opt->backend));
  INFO("mark               : 0x%x\n", opt->mark);
  INFO("mask               : 0x%x\n", opt->mask);
  INFO("regex              : %s\n", opt->regex);
  INFO("script             : %s\n", opt->script);
  INFO("tracer             : %s\n", get_tracer_name_by_id(opt->tracer));
  INFO("output             : %s\n", get_output_name_by_id(opt->output));
  INFO("perf_page_cnt      : %zu\n", opt->perf_page_cnt);
  INFO("perf_sample_period : %zu\n", opt->perf_sample_period);
  INFO("perf_wakeup_events : %u\n", opt->perf_wakeup_events);
  if (opt->enable_probe_server) {
    INFO("probe_server_port  : %u\n", opt->probe_server_port);
  }
  INFO("============ End Options ============\n");
}

static int
get_nr_open(unsigned int *nr_openp)
{
  unsigned int nr_open;

  FILE *f = fopen("/proc/sys/fs/nr_open", "r");
  if (f == NULL) {
    ERROR("fopen /proc/sys/fs/nr_open failed: %s\n", strerror(errno));
    return -1;
  }

  if (fscanf(f, "%u", &nr_open) != 1) {
    ERROR("fscanf failed\n");
    return -1;
  }

  fclose(f);

  *nr_openp = nr_open;

  return 0;
}

static int
do_set_rlimit(void)
{
  int error;
  struct rlimit lim;
  unsigned int nr_open;

  /*
   * Set locked memory limit to infinity
   */
  VERBOSE("Bumping RLIMIT_MEMLOCK (cur: RLIM_INFINITY, max: RLIM_INFINITY)\n");

  lim.rlim_cur = RLIM_INFINITY;
  lim.rlim_max = RLIM_INFINITY;
  error = setrlimit(RLIMIT_MEMLOCK, &lim);
  if (error == -1) {
    ERROR("setrlimit failed: %s\n", strerror(errno));
    return -1;
  }

  /*
   * Get maximum possible value of open files
   */
  error = get_nr_open(&nr_open);
  if (error == -1) {
    ERROR("get_nr_open failed\n");
    return -1;
  }

  /*
   * Set file limit
   */
  VERBOSE("Bumping RLIMIT_MEMLOCK (cur: %u, max: %u)\n", nr_open, nr_open);

  lim.rlim_cur = nr_open;
  lim.rlim_max = nr_open;
  error = setrlimit(RLIMIT_NOFILE, &lim);
  if (error == -1) {
    ERROR("setlimit failed (resource: RLIMIT_NOFILE, cur: %u, max: %u\n",
          nr_open, nr_open);
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
      opt.backend = get_backend_id_by_name(optarg);
      if (opt.backend == IPFT_BACKEND_UNSPEC) {
        ERROR("Unknown backend %s\n", optarg);
        usage();
        goto end;
      }
      break;
    case 'l':
      list = true;
      break;
    case 'm':
      opt.mark = strtoul(optarg, NULL, 0);
      break;
    case 'o':
      opt.output = get_output_id_by_name(optarg);
      if (opt.output == IPFT_OUTPUT_UNSPEC) {
        ERROR("Unknown output %s\n", optarg);
        usage();
        goto end;
      }
      break;
    case 'r':
      opt.regex = strdup(optarg);
      break;
    case 's':
      opt.script = strdup(optarg);
      break;
    case 't':
      opt.tracer = get_tracer_id_by_name(optarg);
      if (opt.tracer == IPFT_TRACER_UNSPEC) {
        ERROR("Unknown tracer %s\n", optarg);
        usage();
        goto end;
      }
      break;
    case 'v':
      verbose = true;
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
    error = do_set_rlimit();
    if (error == -1) {
      ERROR("do_set_rlimit failed\n");
      return -1;
    }
  }

  if (opt.backend == IPFT_BACKEND_UNSPEC) {
    opt.backend = select_backend_for_tracer(opt.tracer);
    if (opt.backend == IPFT_BACKEND_UNSPEC) {
      ERROR("Couldn't find available backend for %s tracer\n",
            get_tracer_name_by_id(opt.tracer));
      return -1;
    }
  }

  if (list) {
    error = list_functions(&opt);
    goto end;
  }

  if (verbose) {
    /* Enable debug print for libbpf */
    libbpf_set_print(debug_print);
    /* Print out all options user provided */
    opt_dump(&opt);
  }

  error = tracer_create(&t, &opt);
  if (error == -1) {
    ERROR("tracer_create failed\n");
    goto end;
  }

  error = tracer_run(t);
  if (error == -1) {
    ERROR("tracer_run failed\n");
    goto end;
  }

end:
  return error == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
