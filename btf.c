#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "ipftrace.h"

int
ipft_btf_fill_sym2info(__unused struct ipft_symsdb *db)
{
  fprintf(stderr, "BTF is not supported currently. Sorry.\n");
  return 0;
}
