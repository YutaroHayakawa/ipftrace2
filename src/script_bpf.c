#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include "ipft.h"

#define EVENT_STRUCT_SYM "__ipft_event_struct"
#define COMPILE_CMD_FMT "%s -target bpf -O2 -g -c -o - %s %s"

const char *bpf_module_preamble =
    "#include <linux/types.h>\n"
    "#include <bpf/bpf_helpers.h>\n"
    "#include <bpf/bpf_core_read.h>\n"
    "\n"
    "#define __ipft_sec_skip __attribute__((section(\"__ipft_skip\")))\n"
    "#define " EVENT_STRUCT_SYM " " EVENT_STRUCT_SYM " __ipft_sec_skip\n";

void
gen_bpf_module_skeleton(void)
{
  printf("%s"
         "\n"
         "struct event {\n"
         "  /* Your fields comes here */\n"
         "  unsigned int len;\n"
         "} __ipft_event_struct;\n"
         "\n"
         "/*\n"
         " * This is an only subset of actual sk_buff definitions but no "
         "problem.\n"
         " * Because BPF-CORE feature of libbpf loader takes care of rewrite "
         "this\n"
         " * program based on actual definition from kernel BTF.\n"
         " */\n"
         "struct sk_buff {\n"
         "  /* Your fields comes here. Below is an example. */\n"
         "  unsigned int len;\n"
         "};\n"
         "\n"
         "__hidden int\n"
         "module(void *ctx, struct sk_buff *skb, __u8 data[64])\n"
         "{\n"
         "  struct event *ev = (struct event *)data;\n"
         "\n"
         "  /* Your logic comes here. Below is an example. */\n"
         "  ev->len = BPF_CORE_READ(skb, len);\n"
         "\n"
         "  return 0;\n"
         "}\n",
         bpf_module_preamble);
}

void
gen_bpf_module_header(void)
{
  printf("#ifndef __IPFT_EXTENSION_H__\n"
         "#define __IPFT_EXTENSION_H__\n"
         "\n"
         "%s"
         "\n"
         "#endif\n",
         bpf_module_preamble);
}

typedef void (*printfn)(FILE *, void *);

struct printer_inst {
  const char *key;
  size_t key_len;
  size_t offset;
  printfn print;
};

/* clang-format off */

#define print_t(t) print_##t

#define decl_print_t(t, fmt)                                                   \
  static void print_##t(FILE *f, void *p)                                      \
  {                                                                            \
    t *target = (t *)p;                                                        \
    fprintf(f, fmt, *target);                                                  \
  }

decl_print_t(uint8_t, "%u") decl_print_t(uint16_t, "%u")
decl_print_t(uint32_t, "%u") decl_print_t(uint64_t, "%lu")
decl_print_t(int8_t, "%d") decl_print_t(int16_t, "%d")
decl_print_t(int32_t, "%d") decl_print_t(int64_t, "%ld")

static void print_bool(FILE *f, void *p)
{
  bool *target = (bool *)p;
  fprintf(f, "%s", *target ? "true" : "false");
}

/*
 * We need to disable clang-format after above function. Otherwise,
 * it will be formatted weirdly like this.
 *
 *     static void print_bool(FILE *f, void *p)
 * {
 *   bool *target = (bool *)p;
 *   fprintf(f, "%s", *target ? "true" : "false");
 * }
 *
 */

/* clang-format on */

static void
print_char(FILE *f, void *p)
{
  char *target = (char *)p;
  fprintf(f, "%c", *target);
}

static void
print_pointer(FILE *f, void *p)
{
  void **target = (void **)p;
  fprintf(f, "%p", *target);
}

struct bpf_script {
  struct ipft_script base;
  struct printer_inst *insts;
  size_t ninsts;
  const char *path;
  bool needs_compile;
};

static const char *
btf_kind_str(__u16 kind)
{
  switch (kind) {
  case BTF_KIND_INT:
    return "integer";
  case BTF_KIND_PTR:
    return "pointer";
  case BTF_KIND_ARRAY:
    return "array";
  case BTF_KIND_STRUCT:
    return "struct";
  case BTF_KIND_UNION:
    return "union";
  case BTF_KIND_ENUM:
    return "enum";
  case BTF_KIND_FWD:
    return "forward";
  case BTF_KIND_TYPEDEF:
    return "typedef";
  case BTF_KIND_VOLATILE:
    return "volatile";
  case BTF_KIND_CONST:
    return "const";
  case BTF_KIND_RESTRICT:
    return "restrict";
  case BTF_KIND_FUNC:
    return "func";
  case BTF_KIND_FUNC_PROTO:
    return "func_proto";
  case BTF_KIND_VAR:
    return "var";
  case BTF_KIND_DATASEC:
    return "datasec";
  case BTF_KIND_FLOAT:
    return "float";
  default:
    return "unknown";
  }
}

static printfn
get_int_printer(__u8 bits, __u8 encoding)
{
  if (encoding & BTF_INT_BOOL) {
    return print_bool;
  }

  if (bits == 8 && encoding & BTF_INT_CHAR) {
    return print_char;
  }

  switch (bits) {
  case 8:
    if (encoding & BTF_INT_SIGNED) {
      return print_t(int8_t);
    } else {
      return print_t(uint8_t);
    }
    break;
  case 16:
    if (encoding & BTF_INT_SIGNED) {
      return print_t(int16_t);
    } else {
      return print_t(uint16_t);
    }
    break;
  case 32:
    if (encoding & BTF_INT_SIGNED) {
      return print_t(int32_t);
    } else {
      return print_t(uint32_t);
    }
    break;
  case 64:
    if (encoding & BTF_INT_SIGNED) {
      return print_t(int64_t);
    } else {
      return print_t(uint64_t);
    }
    break;
  default:
    ERROR("Unsupported bit width %u\n", bits);
    break;
  }

  return NULL;
}

static void
init(struct ipft_script *_script __unused)
{
}

static void
fini(struct ipft_script *_script __unused)
{
}

static int
read_object(FILE *f, uint8_t **bufp, size_t *sizep)
{
  FILE *mem = open_memstream((char **)bufp, sizep);
  if (mem == NULL) {
    ERROR("Failed to open memstream\n");
    return -1;
  }

  while (true) {
    uint8_t buf[256];

    size_t nread = fread(buf, 1, sizeof(buf), f);
    if (nread == 0) {
      break;
    }

    size_t nwrite = fwrite(buf, 1, nread, mem);
    if (nwrite != nread) {
      break;
    }
  }

  fclose(mem);

  return 0;
}

static char *
gen_compile_command(const char *path)
{
  int error;
  char *cmd;

  const char *cc = getenv("CC");
  if (cc == NULL) {
    cc = "clang";
  }

  const char *cflags = getenv("CFLAGS");
  if (cflags == NULL) {
    cflags = "";
  }

  error = asprintf(&cmd, COMPILE_CMD_FMT, cc, cflags, path);
  if (error == -1) {
    ERROR("asprintf failed\n");
    return NULL;
  }

  return cmd;
}

static int
compile_and_read(const char *path, uint8_t **bufp, size_t *sizep)
{
  int error;
  char *cmd;

  cmd = gen_compile_command(path);
  if (cmd == NULL) {
    ERROR("Failed to generate compile command\n");
    return -1;
  }

  VERBOSE("cmd: %s\n", cmd);

  FILE *p = popen(cmd, "r");
  if (p == NULL) {
    ERROR("popen failed\n");
    return -1;
  }

  error = read_object(p, bufp, sizep);
  if (error == -1) {
    ERROR("read_object failed\n");
    goto err0;
  }

  error = pclose(p);
  if (error == -1) {
    ERROR("pclose failed: %s\n", strerror(errno));
    return -1;
  }

  if (error != 0) {
    ERROR("Got an error code from C compiler (command: %s)\n", cmd);
    return -1;
  }

  return 0;

err0:
  pclose(p);
  return -1;
}

static int
get_program(struct ipft_script *_script, uint8_t **bufp, size_t *sizep)
{
  int error;
  struct bpf_script *script = (struct bpf_script *)_script;

  if (script->needs_compile) {
    error = compile_and_read(script->path, bufp, sizep);
    if (error == -1) {
      ERROR("compile_and_read failed\n");
      return -1;
    }
  } else {
    FILE *f = fopen(script->path, "r");
    if (f == NULL) {
      ERROR("failed to open %s\n", script->path);
      return -1;
    }

    error = read_object(f, bufp, sizep);
    if (error == -1) {
      ERROR("read_object failed\n");
      return -1;
    }
  }

  return 0;
}

static int
init_decoder(struct ipft_script *_script, struct bpf_object *bpf)
{
  struct bpf_script *script = (struct bpf_script *)_script;
  const struct btf_type *t;
  struct btf *btf;

  btf = bpf_object__btf(bpf);
  if (btf == NULL) {
    ERROR("BTF not found: %s\n", libbpf_error_string(libbpf_get_error(btf)));
  }

  /*
   * Find event struct variable and extract its type
   */
  const struct btf_type *event_struct_t = NULL;
  for (uint32_t id = 0; (t = btf__type_by_id(btf, id)); id++) {
    if (!btf_is_var(t)) {
      continue;
    }

    const char *name = btf__str_by_offset(btf, t->name_off);
    if (name == NULL) {
      continue;
    }

    if (strcmp(name, EVENT_STRUCT_SYM) != 0) {
      continue;
    }

    t = btf__type_by_id(btf, t->type);
    if (t == NULL) {
      ERROR("Event struct variable has no type associated type\n");
      return -1;
    }

    if (!btf_is_struct(t)) {
      ERROR("Event struct type is not struct, but %d\n", btf_kind(t));
      return -1;
    }

    event_struct_t = t;
    break;
  }

  if (event_struct_t == NULL) {
    ERROR("Couldn't find event struct\n");
    return -1;
  }

  /*
   * Create printer instructions from event struct type
   */
  __u16 nmembers = btf_vlen(event_struct_t);

  struct printer_inst *insts = calloc(nmembers, sizeof(struct printer_inst));
  if (insts == NULL) {
    ERROR("Failed to allocate memory\n");
    return -1;
  }

  VERBOSE("======== BTF Printer Insns ========\n");

  struct btf_member *members = btf_members(event_struct_t);
  for (uint32_t i = 0; i < nmembers; i++) {
    __u16 kind;
    struct printer_inst *inst = insts + i;
    struct btf_member *member = members + i;
    const struct btf_type *member_t =
        btf__type_by_id(btf, btf__resolve_type(btf, member->type));
    const char *member_name = btf__str_by_offset(btf, member->name_off);

    inst->key = member_name;
    inst->key_len = strlen(inst->key);

    if (member->offset % 8 != 0) {
      ERROR("Member %s is not 8bit aligned. Such a member is not supported "
            "yet.\n",
            member_name);
      return -1;
    }

    inst->offset = member->offset / 8;

    kind = btf_kind(member_t);

    switch (kind) {
    case BTF_KIND_INT:
      inst->print =
          get_int_printer(btf_int_bits(member_t), btf_int_encoding(member_t));
      if (inst->print == NULL) {
        ERROR("Failed to get printer function for int type\n");
        return -1;
      }
      break;
    case BTF_KIND_PTR:
      inst->print = print_pointer;
      break;
    default:
      ERROR("Event struct member %s has an unsupported type %s\n", member_name,
            btf_kind_str(kind));
      return -1;
    }

    VERBOSE("[%u] key: %s kind: %s\n", i, inst->key, btf_kind_str(kind));
  }

  VERBOSE("======= END BTF Printer Insns ======\n");

  script->insts = insts;
  script->ninsts = nmembers;

  return 0;
}

static int
decode(struct ipft_script *_script, uint8_t *data, size_t data_len,
       int (*cb)(const char *, size_t, const char *, size_t))
{
  struct bpf_script *script = (struct bpf_script *)_script;
  char *val;
  size_t val_len;

  FILE *f = open_memstream(&val, &val_len);
  if (f == NULL) {
    ERROR("Failed to open memstream\n");
    return -1;
  }

  for (size_t i = 0; i < script->ninsts; i++) {
    struct printer_inst *inst = script->insts + i;

    if (inst->offset >= data_len) {
      ERROR("Invalid offset\n");
      fclose(f);
      return -1;
    }

    inst->print(f, data + inst->offset);

    fflush(f);

    cb(inst->key, inst->key_len, val, val_len);

    fseeko(f, 0, SEEK_SET);
  }

  fclose(f);

  return 0;
}

int
bpf_script_create(struct ipft_script **scriptp, const char *path,
                  bool needs_compile __unused)
{
  struct bpf_script *script = calloc(1, sizeof(*script));
  if (script == NULL) {
    ERROR("Cannot allocate memory\n");
    return -1;
  }

  script->base.init = init;
  script->base.fini = fini;
  script->base.get_program = get_program;
  script->base.init_decoder = init_decoder;
  script->base.decode = decode;
  script->path = path;
  script->needs_compile = needs_compile;

  *scriptp = &script->base;

  return 0;
}
