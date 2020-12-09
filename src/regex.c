/*
 * SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Copyright (C) 2020 Yutaro Hayakawa
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

struct ipft_regex {
  pcre2_code *compiled;
};

int
regex_create(struct ipft_regex **rep, const char *regex)
{
  int error;
  struct ipft_regex *re;
  PCRE2_SIZE error_offset;

  if (regex == NULL) {
    *rep = NULL;
    return 0;
  }

  re = calloc(1, sizeof(*re));
  if (re == NULL) {
    perror("calloc");
    return -1;
  }

  re->compiled = pcre2_compile((PCRE2_SPTR8)regex, PCRE2_ZERO_TERMINATED, 0,
                               &error, &error_offset, NULL);

  if (re->compiled == NULL) {
    PCRE2_UCHAR buffer[256];
    pcre2_get_error_message(error, buffer, sizeof(buffer));
    fprintf(stderr, "PCRE2 compilation failed at offset %ld: %s\n",
        error_offset, buffer);
    return -1;
  }

  *rep = re;

  return 0;
}

bool
regex_match(struct ipft_regex *re, const char *s)
{
  int error;
  pcre2_match_data *match;

  if (re == NULL) {
    return true;
  }

  match = pcre2_match_data_create_from_pattern(re->compiled, NULL);

  error =
      pcre2_match(re->compiled, (PCRE2_SPTR8)s, strlen(s), 0, 0, match, NULL);

  pcre2_match_data_free(match);

  return error < 0 ? false : true;
}
