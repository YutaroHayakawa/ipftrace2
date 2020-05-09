#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipftrace.h"

static struct option options[] = {
    {"debug-format", required_argument, 0, 'f'},
    {"mark", required_argument, 0, 'm'},
    {"regex", optional_argument, 0, 'r'},
    {"script", optional_argument, 0, 's'},
    {"perf-page-count", optional_argument, 0, '0'},
    {NULL, 0, 0, 0},
};

static void usage(void) {
  fprintf(stderr, "Usage: ipftrace [OPTIONS]\n"
                  "\n"
                  "Options:\n"
                  " -f, --debug-format  [DEBUG-FORMAT]    Read the debug "
                  "information with specified format\n"
                  " -m, --mark          [MARK]            Trace the packet "
                  "marked with <mark> [required]\n"
                  " -r, --regex         [REGEX]           Filter the function to trace"
                  "with regex\n"
                  " -s, --script-path   [PATH]            Path to the Lua script file"
                  "\n"
                  "MARK         := hex number\n"
                  "DEBUG-FORMAT := { dwarf, btf }\n"
                  "PATH         := path\n"
                  "\n");
  exit(EXIT_FAILURE);
}

static void opt_init(struct ipft_tracer_opt *opt) {
  opt->mark = 0;
  opt->script_path = NULL;
  opt->debug_info_type = "dwarf";
  opt->perf_page_cnt = 8;
  opt->regex = NULL;
}

static void opt_deinit(struct ipft_tracer_opt *opt) {
  /* Compare address */
  if (opt->debug_info_type != (char *)"dwarf") {
    free(opt->debug_info_type);
  }

  if (opt->script_path != NULL) {
    free(opt->script_path);
  }

  if (opt->regex != NULL) { 
    free(opt->regex);
  }
}

static bool opt_validate(struct ipft_tracer_opt *opt) {
  if (opt->mark == 0) {
    fprintf(stderr, "-m --mark is missing (or specified 0 which is invalid)\n");
    return false;
  }

  if (strcmp(opt->debug_info_type, "dwarf") != 0 &&
      strcmp(opt->debug_info_type, "btf") != 0) {
    fprintf(stderr, "Invalid debug info format %s\n", opt->debug_info_type);
    return false;
  }

  if (opt->perf_page_cnt == 0) {
    fprintf(stderr, "Perf page count should be at least 1\n");
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  int error, c, optind;
  const char *optname;
  struct ipft_tracer_opt opt;

  opt_init(&opt);

  while ((c = getopt_long(argc, argv, "f:m:r:s:0", options, &optind)) != -1) {
    switch (c) {
    case 'f':
      opt.debug_info_type = strdup(optarg);
      break;
    case 'm':
      opt.mark = strtoul(optarg, NULL, 16);
      break;
    case 'r':
      opt.regex = strdup(optarg);
      break;
    case 's':
      opt.script_path = strdup(optarg);
      break;
    case '0':
      optname = options[optind].name;

      if (strcmp(optname, "perf-page-count") == 0) {
        opt.perf_page_cnt = atoi(optarg);
        break;
      }

      break;
    default:
      usage();
      break;
    }
  }

  if (!opt_validate(&opt)) {
    usage();
  }

  error = tracer_run(&opt);
  if (error == -1) {
    fprintf(stderr, "Trace failed with error\n");
    return EXIT_FAILURE;
  }

  opt_deinit(&opt);

  return EXIT_SUCCESS;
}
