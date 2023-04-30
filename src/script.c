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
script_init_decoder(struct ipft_script *script, struct bpf_object *bpf)
{
  return script->init_decoder(script, bpf);
}

int
script_create(struct ipft_script **scriptp, enum ipft_extensions extension,
              const char *path)
{
  if (path == NULL) {
    *scriptp = NULL;
    return 0;
  }

  switch (extension) {
  case IPFT_EXTENSION_LUA:
    return lua_script_create(scriptp, path);
  case IPFT_EXTENSION_BPF_C:
    return bpf_script_create(scriptp, path, true);
  case IPFT_EXTENSION_BPF_O:
    return bpf_script_create(scriptp, path, false);
  default:
    ERROR("Unsupported extension type: %d\n", extension);
  }

  return 0;
}
