#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <luaconf.h>

#include "ipft.h"

struct ipft_script {
  lua_Integer api_version;
  lua_State *L;
};

static bool
script_is_function(lua_State *L, char *name)
{
  bool ret;
  lua_getglobal(L, name);
  ret = lua_isfunction(L, -1);
  lua_pop(L, 1);
  return ret;
}

static bool
script_is_string(lua_State *L, char *name)
{
  bool ret;
  lua_getglobal(L, name);
  ret = lua_isstring(L, -1);
  lua_pop(L, 1);
  return ret;
}

static bool
script_has_init(lua_State *L)
{
  return script_is_function(L, "init");
}

static bool
script_has_fini(lua_State *L)
{
  return script_is_function(L, "fini");
}

static bool
script_has_decode(lua_State *L)
{
  return script_is_function(L, "decode");
}

static bool
script_has_program(lua_State *L)
{
  return script_is_string(L, "program");
}

static lua_Integer
script_get_api_version(lua_State *L)
{
  lua_getglobal(L, "api_version");
  if (!lua_isinteger(L, -1)) {
    ERROR("api_version should be an integer value\n");
    return -1;
  }

  return lua_tointeger(L, -1);
}

static void
script_exec_init(lua_State *L)
{
  if (!script_has_init(L)) {
    return;
  }

  lua_getglobal(L, "init");
  lua_call(L, 0, 0);
}

int
script_create(struct ipft_script **scriptp, const char *path)
{
  int error;
  lua_State *L;
  lua_Integer api_version;
  struct ipft_script *script;

  if (path == NULL) {
    *scriptp = NULL;
    return 0;
  }

  script = malloc(sizeof(*script));
  if (script == NULL) {
    ERROR("Failed to allocate memory\n");
    return -1;
  }

  L = luaL_newstate();

  luaL_openlibs(L);

  error = luaL_dofile(L, path);
  if (error != 0) {
    const char *cause = lua_tostring(L, -1);
    ERROR("Lua error: %s\n", cause);
    return -1;
  }

  api_version = script_get_api_version(L);
  if (api_version == -1) {
    ERROR("Failed to get API version\n");
    return -1;
  }

  /*
   * We currently only support API version 1
   */
  if (api_version != 1) {
    ERROR("Unsupported API version \"" LUA_INTEGER_FMT "\"\n", api_version);
    return -1;
  }

  script_exec_init(L);

  script->L = L;
  *scriptp = script;

  return 0;
}

void
script_exec_fini(struct ipft_script *script)
{
  if (!script_has_fini(script->L)) {
    return;
  }

  lua_getglobal(script->L, "fini");
  lua_call(script->L, 0, 0);
}

int
script_get_program(struct ipft_script *script, uint8_t **imagep,
                   size_t *image_sizep)
{
  uint8_t *image;
  const char *tmp;
  size_t image_size;

  if (!script_has_program(script->L)) {
    return 0;
  }

  lua_getglobal(script->L, "program");

  tmp = lua_tolstring(script->L, -1, &image_size);
  if (tmp == NULL) {
    ERROR("Failed to get module binary\n");
    return -1;
  }

  image = malloc(image_size);
  if (image == NULL) {
    ERROR("Failed to allocate memory\n");
    return -1;
  }

  memcpy(image, tmp, image_size);

  *imagep = image;
  *image_sizep = image_size;

  lua_pop(script->L, 1);

  return 0;
}

int
script_exec_decode(struct ipft_script *script, uint8_t *data, size_t len,
                   int (*cb)(const char *, size_t, const char *, size_t))
{
  int error;
  lua_State *L = script->L;

  if (!script_has_decode(L)) {
    return 0;
  }

  /* A table user returned will be put on top of Lua stack */
  lua_getglobal(L, "decode");
  lua_pushlstring(L, (char *)data, len);
  lua_call(L, 1, 1);

  /* Iterate over the table elements */
  lua_pushnil(L);
  while (lua_next(L, -2) != 0) {
    /* We only support flat string => string table for simplicity */
    if (!lua_isstring(L, -2) || !lua_isstring(L, -1)) {
      ERROR("Invalid key value type, expect string key/value got %s key %s "
            "value\n",
            lua_typename(L, lua_type(L, -2)), lua_typename(L, lua_type(L, -1)));
      return -1;
    }

    /* Callback for each key/value pair */
    size_t klen, vlen;
    const char *k = lua_tolstring(L, -2, &klen);
    const char *v = lua_tolstring(L, -1, &vlen);
    error = cb(k, klen, v, vlen);
    if (error == -1) {
      ERROR("Callback returned with error\n");
      return -1;
    }

    lua_pop(L, 1);
  }

  return 0;
}
