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
    {"verbose", required_argument, 0, 'v'},
    {"mark", required_argument, 0, 'm'},
    {"debug-format", required_argument, 0, 'f'},
    {"mark-offset", required_argument, 0, 0},
    {"vmlinux-path", required_argument, 0, 0},
    {"modules-path", required_argument, 0, 0},
    {NULL, 0, 0, 0},
};

static void usage(void) {
  fprintf(stderr, "Usage: ipftrace [OPTIONS]\n"
                  "\n"
                  "Options:\n"
                  " -v, --verbose       [LEVEL]           Set log level\n"
                  " -m, --mark          [MARK]            Trace the packet "
                  "marked with <mark> [required]\n"
                  " -f, --debug-format  [DEBUG-FORMAT]    Read the debug "
                  "information with specified format\n"
                  "   , --mark-offset   [OFFSET]          Specify the offset "
                  "of the `mark` field of sk_buff manually\n"
                  "   , --vmlinux-path  [PATH]            Specify the vmlinux "
                  "path manually\n"
                  "   , --modules-path  [PATH]            Specify the modules "
                  "path manually\n"
                  "\n"
                  "LEVEL        := { 0, 1, 2, 3, 4 }\n"
                  "MARK         := hex number\n"
                  "DEBUG-FORMAT := { dwarf, btf }\n"
                  "OFFSET       := integer\n"
                  "PATH         := path\n"
                  "\n");
  exit(EXIT_FAILURE);
}

static void opt_init(struct ipft_opt *opt) {
  opt->verbose = 0;
  opt->mark = 0;
  opt->debug_format = "dwarf";
  opt->mark_offset = 0;
  opt->vmlinux_path = NULL;
  opt->modules_path = NULL;
}

static bool opt_validate(struct ipft_opt *opt) {
  if (opt->verbose < 0 || opt->verbose >= IPFT_LOG_MAX) {
    fprintf(stderr, "Invalid verbose level. It should be 0 < level < %d\n",
            IPFT_LOG_MAX);
    return false;
  }

  if (opt->mark == 0) {
    fprintf(stderr, "-m --mark is missing\n");
    return false;
  }

  if (strcmp(opt->debug_format, "dwarf") != 0 &&
      strcmp(opt->debug_format, "btf") != 0) {
    fprintf(stderr, "Invalid debug format %s\n", opt->debug_format);
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  int c, optind;
  const char *optname;
  struct ipft_opt opt;

  opt_init(&opt);

  while ((c = getopt_long(argc, argv, "v:m:f:0", options, &optind)) != -1) {
    switch (c) {
    case 'v':
      opt.verbose = atoi(optarg);
      break;
    case 'm':
      opt.mark = strtoul(optarg, NULL, 16);
      break;
    case 'f':
      opt.debug_format = strdup(optarg);
      break;
    case 0:
      optname = options[optind].name;

      if (strcmp(optname, "mark-offset") == 0) {
        opt.mark_offset = strtoul(optarg, NULL, 10);
        break;
      }

      if (strcmp(optname, "debug-format") == 0) {
        opt.debug_format = strdup(optarg);
        break;
      }

      if (strcmp(optname, "vmlinux-path") == 0) {
        opt.vmlinux_path = strdup(optarg);
        break;
      }

      if (strcmp(optname, "modules-path") == 0) {
        opt.modules_path = strdup(optarg);
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

  do_trace(&opt);

  return EXIT_SUCCESS;
}
