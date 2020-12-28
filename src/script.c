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
script_has_dump(lua_State *L)
{
  return script_is_function(L, "dump");
}

static bool
script_has_emit(lua_State *L)
{
  return script_is_function(L, "emit");
}

static lua_Integer
script_get_api_version(lua_State *L)
{
  lua_getglobal(L, "api_version");
  if (!lua_isinteger(L, -1)) {
    fprintf(stderr, "api_version should be an integer value\n");
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
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  L = luaL_newstate();

  luaL_openlibs(L);

  error = luaL_dofile(L, path);
  if (error != 0) {
    const char *cause = lua_tostring(L, -1);
    fprintf(stderr, "Lua error: %s\n", cause);
    return -1;
  }

  api_version = script_get_api_version(L);
  if (api_version == -1) {
    fprintf(stderr, "Failed to get API version\n");
    return -1;
  }

  /*
   * We currently only support API version 1
   */
  if (api_version != 1) {
    fprintf(stderr, "Unsupported API version \"" LUA_INTEGER_FMT "\"\n",
        api_version);
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
script_exec_emit(struct ipft_script *script,
    uint8_t **imagep, size_t *image_sizep)
{
  uint8_t *image;
  const char *tmp;
  size_t image_size;

  if (!script_has_emit(script->L)) {
    return 0;
  }

  lua_getglobal(script->L, "emit");
  lua_call(script->L, 0, 1);

  tmp = lua_tolstring(script->L, -1, &image_size);
  if (tmp == NULL) {
    fprintf(stderr, "Failed to get module binary\n");
    return -1;
  }

  image = malloc(image_size);
  if (image == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  memcpy(image, tmp, image_size);

  *imagep = image;
  *image_sizep = image_size;

  lua_pop(script->L, 1);

  return 0;
}

char*
script_exec_dump(struct ipft_script *script, uint8_t *data, size_t len)
{
  const char *dump;
  size_t dump_len;

  if (!script_has_dump(script->L)) {
    return NULL;
  }

  lua_getglobal(script->L, "dump");
  lua_pushlstring(script->L, (char *)data, len);
  lua_call(script->L, 1, 1);

  dump = lua_tolstring(script->L, -1, &dump_len);
  if (dump == NULL) {
    fprintf(stderr, "lua_tolstring failed\n");
    return NULL;
  }

  lua_pop(script->L, 1);

  return strndup(dump, dump_len);
}
