#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "ipft.h"

void
script_init(struct ipft_script *script)
{
  script->init(script);
}

void
script_fini(struct ipft_script *script)
{
  script->fini(script);
}

int
script_get_program(struct ipft_script *script, uint8_t **imagep,
                   size_t *image_sizep)
{
  return script->get_program(script, imagep, image_sizep);
}

int
script_decode(struct ipft_script *script, uint8_t *data, size_t len,
              int (*cb)(const char *, size_t, const char *, size_t))
{
  return script->decode(script, data, len, cb);
}

int
script_create(struct ipft_script **scriptp, const char *path)
{
  if (path == NULL) {
    *scriptp = NULL;
    return 0;
  }
  return lua_script_create(scriptp, path);
}
