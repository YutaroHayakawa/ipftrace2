/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>

#include "ipft.h"

static char *default_output_type = "aggregate";

static struct option options[] = {
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
    {NULL, 0, 0, 0},
};

static void
usage(void)
{
  fprintf(stderr,
          "Usage: ipft [OPTIONS]\n"
          "\n"
          "Options:\n"
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
          " -v, --verbose                            Turn on debug message\n"
          "   , --perf-page-count    [NUMBER]        Number of pages to use "
          "with perf (default: 8)\n"
          "   , --perf-sample-period [NUMBER]        Number of pages to use "
          "with perf (default: 1)\n"
          "   , --perf-wakeup-events [NUMBER]        Number of pages to use "
          "with perf (default: 1)\n"
          "   , --no-set-rlimit                      Don't set rlimit\n"
          "\n"
          "OUTPUT-FORMAT := { aggregate, json }\n"
          "\n");
}

static void
opt_init(struct ipft_tracer_opt *opt)
{
  opt->mark = 0;
  opt->mask = 0xffffffff;
  opt->output_type = default_output_type;
  opt->perf_page_cnt = 8;
  opt->perf_sample_period = 1;
  opt->perf_wakeup_events = 1;
  opt->regex = NULL;
  opt->script = NULL;
  opt->verbose = false;
}

static void
opt_dump(struct ipft_tracer_opt *opt)
{
  fprintf(stderr, "============   Options   ============\n");
  fprintf(stderr, "mark               : 0x%x\n", opt->mark);
  fprintf(stderr, "mask               : 0x%x\n", opt->mask);
  fprintf(stderr, "regex              : %s\n", opt->regex);
  fprintf(stderr, "script             : %s\n", opt->script);
  fprintf(stderr, "output_type        : %s\n", opt->output_type);
  fprintf(stderr, "perf_page_cnt      : %zu\n", opt->perf_page_cnt);
  fprintf(stderr, "perf_sample_period : %zu\n", opt->perf_sample_period);
  fprintf(stderr, "perf_wakeup_events : %u\n", opt->perf_wakeup_events);
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

  if (strcmp(opt->output_type, "aggregate") != 0 &&
      strcmp(opt->output_type, "json") != 0) {
    fprintf(stderr, "Invalid output format %s\n", opt->output_type);
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
    fprintf(stderr, "Bumping RLIMIT_MEMLOCK (cur: RLIM_INFINITY, max: RLIM_INFINITY)\n");
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
    fprintf(stderr, "Bumping RLIMIT_MEMLOCK (cur: %u, max: %u)\n", nr_open, nr_open);
  }

  lim.rlim_cur = nr_open;
  lim.rlim_max = nr_open;
  error = setrlimit(RLIMIT_NOFILE, &lim);
  if (error == -1) {
    fprintf(stderr, "setlimit failed (resource: RLIMIT_NOFILE, cur: %u, max: %u\n", nr_open, nr_open);
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

  while ((c = getopt_long(argc, argv, "hlm:o:r:s:v", options, &optind)) != -1) {
    switch (c) {
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

      break;
    default:
      usage();
      goto end;
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

  if (set_rlimit) {
    error = do_set_rlimit(opt.verbose);
    if (error == -1) {
      fprintf(stderr, "do_set_rlimit failed\n");
      return -1;
    }
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
