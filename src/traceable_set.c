/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "khash.h"
#include "ipftrace.h"

KHASH_MAP_INIT_STR(traceable_set, int)

struct ipft_traceable_set {
  khash_t(traceable_set) *set;
};

static int
put(khash_t(traceable_set) *set, char *sym)
{
  char *k;
  int missing;
  __unused khint_t iter;

  k = strdup(sym);
  if (k == NULL) {
    return -1;
  }

  iter = kh_put(traceable_set, set, k, &missing);
  if (missing == -1) {
    fprintf(stderr, "kh_put failed\n");
    free(k);
    return -1;
  } else if (!missing) {
    free(k);
  }

  return 0;
}

static int
read_available_filter_functions(khash_t(traceable_set) *set)
{
  FILE *f;
  int error;
  ssize_t nread;
  size_t len = 0;
  char *line = NULL;

  f = fopen("/sys/kernel/debug/tracing/available_filter_functions", "r");
  if (f == NULL) {
    perror("fopen");
    return -1;
  }

  while ((nread = getline(&line, &len, f)) != -1) {
    char sym[129] = {0};
    char *cur = line;
    while (cur - line != 128) {
      sym[cur - line] = *cur;
      cur++;
      if (*cur == '\n' || *cur == ' ') {
        error = put(set, sym);
        if (error == -1) {
          fprintf(stderr, "Failed to put symbol to the set\n");
          return -1;
        }
        break;
      }
    }
  }

  free(line);
  fclose(f);

  return 0;
}

bool
traceable_set_is_traceable(struct ipft_traceable_set *tset, const char *sym)
{
  khint_t iter;

  iter = kh_get(traceable_set, tset->set, sym);
  if (iter == kh_end(tset->set)) {
    return false;
  }

  return true;
}

int
traceable_set_create(struct ipft_traceable_set **tsetp)
{
  int error;
  struct ipft_traceable_set *tset;

  tset = malloc(sizeof(*tset));
  if (tset == NULL) {
    perror("malloc");
    return -1;
  }

  tset->set = kh_init(traceable_set);
  if (tset->set == NULL) {
    perror("kh_init");
    goto err0;
  }

  error = read_available_filter_functions(tset->set);
  if (error == -1) {
    fprintf(stderr, "read_available_filter_functions failed\n");
    return -1;
  }

  *tsetp = tset;

  return 0;

err0:
  free(tset);
  return -1;
}

void
traceable_set_destroy(struct ipft_traceable_set *tset)
{
  const char *k;
  __unused int v;
  kh_foreach(tset->set, k, v, free((char *)k););
  free(tset);
}
