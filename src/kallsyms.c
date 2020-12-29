/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "khash.h"

#include "ipftrace.h"

/*
 * Took from bcc (https://github.com/iovisor/bcc)
 */
#ifdef __x86_64__
// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
const unsigned long long kernel_addr_space = 0x00ffffffffffffff;
#else
const unsigned long long kernel_addr_spacee = 0x0;
#endif

int
kallsyms_fill_addr2sym(struct ipft_symsdb *db)
{
  FILE *f;
  int error;
  uint64_t addr;
  char line[2048];
  char *symname, *endsym;
  struct ipft_syminfo *si;

  f = fopen("/proc/kallsyms", "r");
  if (f == NULL) {
    perror("fopen");
    return -1;
  }

  if (geteuid() != 0) {
    fprintf(
        stderr,
        "Non-root users cannot read address info. Please execute with root.\n");
    return -1;
  }

  while (fgets(line, sizeof(line), f)) {
    addr = strtoull(line, &symname, 16);
    if (addr == 0 || addr == ULLONG_MAX) {
      continue;
    }

    if (addr < kernel_addr_space) {
      continue;
    }

    symname++;

    // Ignore data symbols
    if (*symname == 'b' || *symname == 'B' || *symname == 'd' ||
        *symname == 'D' || *symname == 'r' || *symname == 'R') {
      continue;
    }

    symname += 2;
    endsym = symname;
    while (*endsym && !isspace(*endsym)) {
      endsym++;
    }

    *endsym = '\0';

    /*
     * IP points to 1byte after than the address kallsyms reports
     */
    addr += 1;

    /*
     * Only add the symbols which are used
     */
    error = symsdb_get_sym2info(db, symname, &si);
    if (error == -1) {
      continue;
    }

    /*
     * This shouldn't fail
     */
    error = symsdb_put_addr2sym(db, addr, symname);
    if (error == -1) {
      fprintf(stderr, "symsdb_put_addr2sym failed\n");
      return -1;
    }
  }

  fclose(f);

  return 0;
}
