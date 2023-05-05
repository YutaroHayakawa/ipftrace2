#include <linux/btf.h>
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
#define FORMAT_SPECIFIER_TAG "ipft:fmt:"
#define FORMAT_HEX "hex"
#define FORMAT_ENUM "enum"
#define FORMAT_ENUM_FLAGS "enum_flags"
#define COMPILE_CMD_FMT "%s -target bpf -O2 -g -c -o - %s %s"

const char *bpf_module_preamble =
    "#include <linux/types.h>\n"
    "#include <bpf/bpf_helpers.h>\n"
    "#include <bpf/bpf_core_read.h>\n"
    "\n"
    "#define __ipft_sec_skip __attribute__((section(\"__ipft_skip\")))\n"
    "#define __ipft_ref(name) name __ipft_sec_skip\n"
    "#define " EVENT_STRUCT_SYM " " EVENT_STRUCT_SYM " __ipft_sec_skip\n"
    "#define __ipft_fmt_hex __attribute__((btf_decl_tag(\"" FORMAT_SPECIFIER_TAG
        FORMAT_HEX "\")))\n"
    "#define __ipft_fmt_enum(ref) "
    "__attribute__((btf_decl_tag(\"" FORMAT_SPECIFIER_TAG FORMAT_ENUM
    ":\" #ref)))\n"
    "#define __ipft_fmt_enum_flags(ref) "
    "__attribute__((btf_decl_tag(\"" FORMAT_SPECIFIER_TAG FORMAT_ENUM_FLAGS
    ":\" #ref)))\n";

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

typedef void (*printfn)(FILE *, void *, void *);

enum formatter_types {
  FORMATTER_TYPE_DEFAULT,
  FORMATTER_TYPE_HEX,
  FORMATTER_TYPE_ENUM,
  FORMATTER_TYPE_ENUM_FLAGS,
};

static const char *
formatter_type_str(enum formatter_types t)
{
  switch (t) {
  case FORMATTER_TYPE_DEFAULT:
    return "default";
  case FORMATTER_TYPE_HEX:
    return FORMAT_HEX;
  case FORMATTER_TYPE_ENUM:
    return FORMAT_ENUM;
  case FORMATTER_TYPE_ENUM_FLAGS:
    return FORMAT_ENUM_FLAGS;
  default:
    return "unknown";
  }
}

struct printer_inst {
  const char *key;
  size_t key_len;
  size_t offset;
  printfn print;
  enum formatter_types formatter;
  void *data;
};

struct enum_data {
  __u16 nmembers;
  const char **member_names;
  __s32 *member_values;
};

/* clang-format off */

#define print_t(t) print_##t

#define decl_print_t(t, fmt)                                                   \
  static void print_##t(FILE *f, void *p, void *data __unused)                 \
  {                                                                            \
    t *target = (t *)p;                                                        \
    fprintf(f, fmt, *target);                                                  \
  }

decl_print_t(uint8_t, "%u")
decl_print_t(uint16_t, "%u")
decl_print_t(uint32_t, "%u")
decl_print_t(uint64_t, "%lu")
decl_print_t(int8_t, "%d")
decl_print_t(int16_t, "%d")
decl_print_t(int32_t, "%d")
decl_print_t(int64_t, "%ld")

#define print_hex_t(t) print_hex_##t

#define decl_print_hex_t(t, fmt)                                               \
  static void print_hex_##t(FILE *f, void *p, void *data __unused)             \
  {                                                                            \
    t *target = (t *)p;                                                        \
    fprintf(f, "0x" fmt, *target);                                             \
  }

decl_print_hex_t(uint8_t, "%x")
decl_print_hex_t(uint16_t, "%x")
decl_print_hex_t(uint32_t, "%x")
decl_print_hex_t(uint64_t, "%lx")

#define print_enum_t(t) print_enum_##t

#define decl_print_enum_t(t)                                                   \
  static void print_enum_##t(FILE *f, void *p, void *_data)                    \
  {                                                                            \
    t *target = (t *)p;                                                        \
    struct enum_data *data = (struct enum_data *)_data;                        \
    for (__u16 i = 0; i < data->nmembers; i++) {                               \
      if (*target == (t)data->member_values[i]) {                              \
        fprintf(f, "%s", data->member_names[i]);                               \
        return;                                                                \
      }                                                                        \
    }                                                                          \
    fprintf(f, "<none>");                                                      \
  }

decl_print_enum_t(uint8_t)
decl_print_enum_t(uint16_t)
decl_print_enum_t(uint32_t)
decl_print_enum_t(uint64_t)

#define print_enum_flags_t(t) print_enum_flags_##t

#define decl_print_enum_flags_t(t) \
  static void print_enum_flags_##t(FILE *f, void *p, void *_data) \
  { \
    t *target = (t *)p; \
    bool matched = false; \
    struct enum_data *data = (struct enum_data *)_data; \
    for (__u16 i = 0; i < data->nmembers; i++) { \
      if (*target & data->member_values[i]) { \
        matched = true; \
        if (i == 0) { \
          fprintf(f, "%s", data->member_names[i]); \
        } else { \
          fprintf(f, "|%s", data->member_names[i]); \
        } \
      } \
    } \
    if (!matched) { \
      fprintf(f, "<none>"); \
    } \
  }

decl_print_enum_flags_t(uint8_t)
decl_print_enum_flags_t(uint16_t)
decl_print_enum_flags_t(uint32_t)
decl_print_enum_flags_t(uint64_t)

static void print_bool(FILE *f, void *p, void *data __unused)
{
  bool *target = (bool *)p;
  fprintf(f, "%s", *target ? "true" : "false");
}

/*
 * We need to disable clang-format after above function. Otherwise,
 * it will be formatted weirdly like this.
 *
 *     static void print_bool(FILE *f, void *p, void *data __unused)
 * {
 *   bool *target = (bool *)p;
 *   fprintf(f, "%s", *target ? "true" : "false");
 * }
 *
 */

/* clang-format on */

static void
print_char(FILE *f, void *p, void *data __unused)
{
  char *target = (char *)p;
  fprintf(f, "%c", *target);
}

static void
print_pointer(FILE *f, void *p, void *data __unused)
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

static printfn
get_hex_printer(__u8 bits)
{
  switch (bits) {
  case 8:
    return print_hex_t(uint8_t);
  case 16:
    return print_hex_t(uint16_t);
  case 32:
    return print_hex_t(uint32_t);
  case 64:
    return print_hex_t(uint64_t);
  default:
    ERROR("Unsupported bit width %u\n", bits);
    break;
  }
  return NULL;
}

static printfn
get_enum_printer(__u8 bits)
{
  switch (bits) {
  case 8:
    return print_enum_t(uint8_t);
  case 16:
    return print_enum_t(uint16_t);
  case 32:
    return print_enum_t(uint32_t);
  case 64:
    return print_enum_t(uint64_t);
  default:
    ERROR("Unsupported bit width %u\n", bits);
    break;
  }
  return NULL;
}

static printfn
get_enum_flags_printer(__u8 bits)
{
  switch (bits) {
  case 8:
    return print_enum_flags_t(uint8_t);
  case 16:
    return print_enum_flags_t(uint16_t);
  case 32:
    return print_enum_flags_t(uint32_t);
  case 64:
    return print_enum_flags_t(uint64_t);
  default:
    ERROR("Unsupported bit width %u\n", bits);
    break;
  }
  return NULL;
}

static void *
get_enum_data(struct btf *btf, const struct btf_type *t)
{
  struct enum_data *data;

  data = calloc(1, sizeof(*data));
  if (data == NULL) {
    ERROR("Cannot allocate memory\n");
    return NULL;
  }

  data->nmembers = btf_vlen(t);

  data->member_values = calloc(data->nmembers, sizeof(*data->member_values));
  if (data->member_values == NULL) {
    ERROR("Cannot allocate memory\n");
    return NULL;
  }

  data->member_names = calloc(data->nmembers, sizeof(*data->member_names));
  if (data->member_names == NULL) {
    ERROR("Cannot allocate memory\n");
    return NULL;
  }

  for (__u16 i = 0; i < data->nmembers; i++) {
    struct btf_enum *e = btf_enum(t) + i;
    data->member_values[i] = e->val;
    data->member_names[i] = btf__name_by_offset(btf, e->name_off);
  }

  return (void *)data;
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

static bool
is_event_struct(struct btf *btf, const struct btf_type *t)
{
  const char *name = btf__str_by_offset(btf, t->name_off);
  if (name == NULL) {
    return false;
  }

  if (strcmp(name, EVENT_STRUCT_SYM) != 0) {
    return false;
  }

  t = btf__type_by_id(btf, t->type);
  if (t == NULL) {
    ERROR("Event struct variable has no type associated type\n");
    return false;
  }

  if (!btf_is_struct(t)) {
    ERROR("Event struct type is not struct, but %d\n", btf_kind(t));
    return false;
  }

  return true;
}

static bool
is_format_specifier(struct btf *btf, const struct btf_type *t)
{
  const char *name = btf__name_by_offset(btf, t->name_off);

  if (strstr(name, FORMAT_SPECIFIER_TAG) != name) {
    return false;
  }

  return true;
}

static enum formatter_types
get_formatter_type(const char *tag, char **refp)
{
  char *fmt = strstr(tag, FORMAT_SPECIFIER_TAG);
  if (fmt != tag) {
    goto err0;
  }

  fmt += strlen(FORMAT_SPECIFIER_TAG);

  if (strstr(fmt, FORMAT_HEX) == fmt) {
    *refp = NULL;
    return FORMATTER_TYPE_HEX;
  }

  if (strstr(fmt, FORMAT_ENUM_FLAGS) == fmt) {
    *refp = fmt + strlen(FORMAT_ENUM_FLAGS) + 1;
    return FORMATTER_TYPE_ENUM_FLAGS;
  }

  if (strstr(fmt, FORMAT_ENUM) == fmt) {
    *refp = fmt + strlen(FORMAT_ENUM) + 1;
    return FORMATTER_TYPE_ENUM;
  }

  ERROR("Unknown format specifier: %s\n", fmt);

  return FORMATTER_TYPE_DEFAULT;

err0:
  ERROR("Invalid format specifier: %s\n", tag);
  return FORMATTER_TYPE_DEFAULT;
}

#define MAX_FMT_SPECS 64

struct btf_summary {
  struct btf *btf;
  const struct btf_type *event_struct_t;
  __u16 nmembers;
  const struct btf_member *members;
  const struct btf_type **member_types;
  const char **member_names;
  enum formatter_types *fmt_types;
  const struct btf_type **fmt_refs;
};

static int
btf_summary_create(struct btf_summary **summaryp, struct bpf_object *bpf)
{
  __s32 tid;
  struct btf *btf;
  const struct btf_type *t;
  struct btf_summary *summary;

  summary = calloc(1, sizeof(*summary));
  if (summary == NULL) {
    ERROR("Cannot allocate memory");
    return -1;
  }

  btf = bpf_object__btf(bpf);
  if (btf == NULL) {
    ERROR("BTF not found: %s\n", libbpf_error_string(libbpf_get_error(btf)));
    return -1;
  }

  summary->btf = btf;

  tid = btf__find_by_name_kind(summary->btf, EVENT_STRUCT_SYM, BTF_KIND_VAR);
  if (tid < 0) {
    ERROR("Failed to find event struct var: %s\n", libbpf_error_string(tid));
    return -1;
  }

  t = btf__type_by_id(summary->btf, tid);
  if (!is_event_struct(summary->btf, t)) {
    ERROR("Found event struct variable, but has invalid type\n");
    return -1;
  }

  summary->event_struct_t = btf__type_by_id(summary->btf, t->type);
  summary->nmembers = btf_vlen(summary->event_struct_t);
  summary->members = btf_members(summary->event_struct_t);

  summary->member_types =
      calloc(summary->nmembers, sizeof(*summary->member_types));
  if (summary->member_types == NULL) {
    ERROR("Cannot allocate memory\n");
    return -1;
  }

  summary->member_names =
      calloc(summary->nmembers, sizeof(*summary->member_names));
  if (summary->member_names == NULL) {
    ERROR("Cannot allocate memory\n");
    return -1;
  }

  for (__u16 i = 0; i < summary->nmembers; i++) {
    const struct btf_member *m = summary->members + i;
    summary->member_types[i] =
        btf__type_by_id(btf, btf__resolve_type(summary->btf, m->type));
    summary->member_names[i] = btf__name_by_offset(btf, m->name_off);
  }

  /* Collect all format specifiers */
  summary->fmt_types = calloc(summary->nmembers, sizeof(*summary->fmt_types));
  if (summary->fmt_types == NULL) {
    ERROR("Cannot allocate memory\n");
    return -1;
  }

  summary->fmt_refs = calloc(summary->nmembers, sizeof(*summary->fmt_refs));
  if (summary->fmt_refs == NULL) {
    ERROR("Cannot allocate memory\n");
    return -1;
  }

  for (uint32_t id = 0; (t = btf__type_by_id(summary->btf, id)); id++) {
    if (btf_is_decl_tag(t) && is_format_specifier(summary->btf, t)) {
      char *ref;
      enum formatter_types ft;
      struct btf_decl_tag *tag = btf_decl_tag(t);
      if (tag->component_idx == -1 || tag->component_idx >= summary->nmembers) {
        ERROR("Tag %s is pointing to invalid struct field\n",
              btf__name_by_offset(summary->btf, t->name_off));
        return -1;
      }

      ft = get_formatter_type(btf__name_by_offset(btf, t->name_off), &ref);
      if (ft == FORMATTER_TYPE_DEFAULT) {
        ERROR("Failed to get formatter type\n");
        return -1;
      }

      summary->fmt_types[tag->component_idx] = ft;

      if (ft == FORMATTER_TYPE_ENUM_FLAGS || ft == FORMATTER_TYPE_ENUM) {
        __s32 tid;
        const struct btf_type *t;

        /* This is O(N) where N is number of types in the BTF. Very inefficient,
         * but it's ok for now. We can optimize this at anytime later.
         */
        tid = btf__find_by_name_kind(summary->btf, ref, BTF_KIND_VAR);
        if (tid < 0) {
          ERROR("Couldn't find enum reference %s\n", ref);
          return -1;
        }

        t = btf__type_by_id(summary->btf, tid);

        t = btf__type_by_id(summary->btf, t->type);
        if (btf_kind(t) != BTF_KIND_ENUM) {
          ERROR("non-enum reference associated enum_flags format specifier\n");
          return -1;
        }

        summary->fmt_refs[tag->component_idx] = t;
      }

      continue;
    }
  }

  *summaryp = summary;

  return 0;
}

static printfn
get_default_printer(const struct btf_type *t)
{
  __u16 kind = btf_kind(t);
  switch (kind) {
  case BTF_KIND_INT:
    return get_int_printer(btf_int_bits(t), btf_int_encoding(t));
  case BTF_KIND_PTR:
    return print_pointer;
  default:
    ERROR("Cannot get printer for type %s\n", btf_kind_str(kind));
    return NULL;
  }
}

static int
init_decoder(struct ipft_script *_script, struct bpf_object *bpf)
{
  struct bpf_script *script = (struct bpf_script *)_script;
  struct btf_summary *summary;
  int error;

  error = btf_summary_create(&summary, bpf);
  if (error == -1) {
    ERROR("btf_summary_create failed\n");
    return -1;
  }

  /*
   * Create printer instructions from event struct type
   */
  struct printer_inst *insts =
      calloc(summary->nmembers, sizeof(struct printer_inst));
  if (insts == NULL) {
    ERROR("Failed to allocate memory\n");
    return -1;
  }

  for (uint32_t i = 0; i < summary->nmembers; i++) {
    struct printer_inst *inst = insts + i;
    const struct btf_member *m = summary->members + i;
    const struct btf_type *mt = summary->member_types[i];
    const char *name = summary->member_names[i];
    const enum formatter_types ft = summary->fmt_types[i];
    const struct btf_type *ref_t = summary->fmt_refs[i];
    printfn printer;
    void *data = NULL;

    inst->key = summary->member_names[i];
    inst->key_len = strlen(inst->key);

    if (m->offset % 8 != 0) {
      ERROR("Member %s is not 8bit aligned. Such a member is not supported "
            "yet.\n",
            inst->key);
      return -1;
    }

    inst->offset = m->offset / 8;

    switch (ft) {
    case FORMATTER_TYPE_HEX:
      printer = get_hex_printer(btf_int_bits(mt));
      break;
    case FORMATTER_TYPE_ENUM:
      printer = get_enum_printer(btf_int_bits(mt));
      data = get_enum_data(summary->btf, ref_t);
      if (data == NULL) {
        ERROR("Cannot get enum_flags data\n");
        return -1;
      }
      break;
    case FORMATTER_TYPE_ENUM_FLAGS:
      printer = get_enum_flags_printer(btf_int_bits(mt));
      data = get_enum_data(summary->btf, ref_t);
      if (data == NULL) {
        ERROR("Cannot get enum_flags data\n");
        return -1;
      }
      break;
    default:
      printer = get_default_printer(mt);
    }

    if (printer == NULL) {
      ERROR("Cannot format member %s with %s formatter\n", name,
            formatter_type_str(ft));
      return -1;
    }

    inst->formatter = ft;
    inst->print = printer;
    inst->data = data;
  }

  VERBOSE("======== BTF Printer Insns ========\n");
  for (uint32_t i = 0; i < summary->nmembers; i++) {
    struct printer_inst *inst = insts + i;
    const struct btf_type *t = summary->member_types[i];
    VERBOSE("[%u] key: %s kind: %s formatter: %s\n", i, inst->key,
            btf_kind_str(btf_kind(t)), formatter_type_str(inst->formatter));
  }
  VERBOSE("======= END BTF Printer Insns ======\n");

  script->insts = insts;
  script->ninsts = summary->nmembers;

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

    inst->print(f, data + inst->offset, inst->data);

    fflush(f);

    cb(inst->key, inst->key_len, val, val_len);

    fseeko(f, 0, SEEK_SET);
  }

  fclose(f);

  return 0;
}

int
bpf_script_create(struct ipft_script **scriptp, const char *path,
                  bool needs_compile)
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
