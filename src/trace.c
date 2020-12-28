#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>

#include <gelf.h>
#include <libelf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipftrace.h"
#include "ipft.bpf.o.h"

struct ipft_tracer {
  struct bpf_object *bpf;
  struct ipft_regex *re;
  struct ipft_symsdb *sdb;
  struct ipft_output *out;
  struct ipft_tracedb *tdb;
  struct ipft_script *script;
  struct ipft_debuginfo *dinfo;
  struct ipft_traceable_set *tset;
  struct perf_buffer *pb;
};

struct target_elf {
  FILE *fp;
  Elf *elf;
  Elf64_Ehdr ehdr;
  Elf_Scn *symtab_scn;
  Elf_Scn *text_scn;
  int text_sh_idx;
  int strtab_shidx;
};

struct module_elf {
  Elf *elf;
  Elf64_Ehdr ehdr;
  Elf_Scn *text_scn;
  Elf_Scn *symtab_scn;
  int strtab_shidx;
};

static struct bpf_insn default_module[] = {
  { BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 0 },
  { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 },
};

static int
set_rlimit(struct ipft_symsdb *sdb)
{
  int error;
  size_t nfiles;
  struct rlimit lim;

  /*
   * Rough estimations for various file descriptors like eBPF
   * program, maps or perf events and kprobe events. This is
   * the "required" number of file descriptors.
   */
  nfiles = 32 + symsdb_get_sym2info_total(sdb);

  /*
   * Set locked memory limit to infinity
   */
  lim.rlim_cur = RLIM_INFINITY;
  lim.rlim_max = RLIM_INFINITY;
  error = setrlimit(RLIMIT_MEMLOCK, &lim);
  if (error == -1) {
    perror("setrlimit");
    return -1;
  }

  /*
   * Set file limit
   */
  error = getrlimit(RLIMIT_NOFILE, &lim);
  if (error == -1) {
    perror("getrlimit");
    return -1;
  }

  if (lim.rlim_cur < nfiles && lim.rlim_cur != RLIM_INFINITY) {
    lim.rlim_cur = nfiles;
  }

  if (lim.rlim_max != RLIM_INFINITY && lim.rlim_max < lim.rlim_cur) {
    lim.rlim_max = lim.rlim_cur;
  }

  error = setrlimit(RLIMIT_NOFILE, &lim);
  if (error == -1) {
    perror("setrlimit");
    return -1;
  }

  return 0;
}

static int
open_target_elf(uint8_t *image, size_t image_size, struct target_elf **objp)
{
  char *name;
  size_t wsize;
  Elf_Scn *scn;
  GElf_Shdr sh;
  struct target_elf *obj;

  elf_version(EV_CURRENT);

  obj = malloc(sizeof(*obj));
  if (obj == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  /*
   * We cannot use elf_memory in here, since the descriptor
   * returned by it is immutable. Thus, we need to create
   * tmpfile and write the ELF image to it.
   */
  obj->fp = tmpfile();
  if (obj->fp == NULL) {
    fprintf(stderr, "Failed to open tmpfile\n");
    return -1;
  }

  wsize = fwrite(image, image_size, 1, obj->fp);
  if (wsize != 1) {
    fprintf(stderr, "Failed to write image to tmpfile\n");
    return -1;
  }

  /* Need to reset offset before reading ELF */
  fseek(obj->fp, 0, SEEK_SET);

  obj->elf = elf_begin(fileno(obj->fp), ELF_C_RDWR, NULL);
  if (obj->elf == NULL) {
    fprintf(stderr, "Failed to open ELF object from memory\n");
    return -1;
  }

  /* First find symtab section */
  scn = NULL;
  while ((scn = elf_nextscn(obj->elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &sh) != &sh) {
      return -1;
    }

    if (sh.sh_type == SHT_SYMTAB) {
      obj->symtab_scn = scn;
      obj->strtab_shidx = sh.sh_link;
      break;
    }
  }

  if (obj->symtab_scn == NULL) {
    fprintf(stderr, "Cannot find symtab section\n");
    return -1;
  }

  /* Next find .text section */
  scn = NULL;
  while ((scn = elf_nextscn(obj->elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &sh) != &sh) {
      return -1;
    }

    name = elf_strptr(obj->elf, obj->strtab_shidx, sh.sh_name);

    if (sh.sh_type == SHT_PROGBITS && sh.sh_flags & SHF_EXECINSTR) {
      if (strcmp(".text", name) == 0) {
        obj->text_scn = scn;
        obj->text_sh_idx = elf_ndxscn(scn);
        break;
      }
    }
  }

  *objp = obj;

  return 0;
}

static void
close_target_elf(struct target_elf *target)
{
  elf_end(target->elf);
  fclose(target->fp);
}

static int
open_module_elf(uint8_t *image, size_t image_size, struct module_elf **objp)
{
  char *name;
  Elf_Scn *scn;
  GElf_Shdr sh;
  Elf_Data *data;
  struct module_elf *obj;

  elf_version(EV_CURRENT);

  obj = calloc(1, sizeof(*obj));
  if (obj == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  obj->elf = elf_memory((char *)image, image_size);
  if (obj->elf == NULL) {
    fprintf (stderr, "Couldn't open ELF image: %s\n", elf_errmsg(-1));
    return -1;
  }

  // First find symtab section
  scn = NULL;
  while ((scn = elf_nextscn(obj->elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &sh) != &sh) {
      return -1;
    }

    if (sh.sh_type == SHT_SYMTAB) {
      obj->symtab_scn = scn;
      obj->strtab_shidx = sh.sh_link;
      break;
    }
  }

  if (obj->symtab_scn == NULL) {
    fprintf(stderr, "Cannot find symtab section\n");
    return -1;
  }

  /* Next find .text section */
  scn = NULL;
  while ((scn = elf_nextscn(obj->elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &sh) != &sh) {
      return -1;
    }

    data = elf_getdata(scn, NULL);
    name = elf_strptr(obj->elf, obj->strtab_shidx, sh.sh_name);

    if (sh.sh_type == SHT_PROGBITS && sh.sh_flags & SHF_EXECINSTR) {
      if (strcmp(".text", name) == 0) {
        if (data->d_size > 0) {
          obj->text_scn = scn;
          break;
        } else {
          fprintf(stderr, ".text section is empty\n");
          return -1;
        }
      }
    }
  }

  *objp = obj;

  return 0;
}

static void
close_module_elf(struct module_elf *module)
{
  elf_end(module->elf);
}

static int
get_module_image(struct module_elf *obj,
    uint8_t **imagep, size_t *image_sizep)
{
  char *name;
  GElf_Shdr sh;
  GElf_Sym *sym;
  Elf_Scn *scn, *target_scn;
  Elf_Data *data, *target_data;

  scn = obj->symtab_scn;
  if (gelf_getshdr(scn, &sh) != &sh) {
    fprintf(stderr, "Couldn't get shdr of module prog sec\n");
    return -1;
  }

  data = elf_getdata(scn, NULL);
  if (data == NULL) {
    fprintf(stderr, "Faield to get data\n");
    return -1;
  }

  /* Find the function named "module" and get its content */
  for (size_t i = 0; i < data->d_size / sizeof(*sym); i++) {
    sym = data->d_buf + sizeof(*sym) * i;

    name = elf_strptr(obj->elf, obj->strtab_shidx, sym->st_name);
    if (strcmp(name, "module") != 0) {
      continue;
    }

    // Check the symbol type and make sure it is a function STT_FUNC
    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
      fprintf(stderr, "Symbol module is not a function\n");
      return -1;
    }

    target_scn = elf_getscn(obj->elf, sym->st_shndx);
    target_data = elf_getdata(target_scn, NULL);

    *imagep = target_data->d_buf + sym->st_value;
    *image_sizep = target_data->d_size;

    return 0;
  }

  fprintf(stderr, "Cannot find module function\n");

  return -1;
}

static int
do_link(struct target_elf *target,
    struct module_elf *module)
{
  int error;
  char *name;
  GElf_Sym *sym;
  uint8_t *image;
  size_t image_size;
  Elf_Data *data, *symtab_data;

  /* Copy module binary from module ELF */
  if (module != NULL) {
    error = get_module_image(module, &image, &image_size);
    if (error != 0) {
      fprintf(stderr, "get_module_image failed\n");
      return -1;
    }
  } else {
    image = (uint8_t *)default_module;
    image_size = sizeof(default_module);
  }

  /* Copy module binary to target ELF */
  data = elf_getdata(target->text_scn, NULL);
  data->d_buf = image;
  data->d_size = image_size;
  data->d_align = 8;

  /* Fill symtab */
  symtab_data = elf_getdata(target->symtab_scn, NULL);
  if (symtab_data == NULL) {
    fprintf(stderr, "Couldn't get symtab data\n");
    return -1;
  }

  for (size_t i = 0; i < symtab_data->d_size / sizeof(*sym); i++) {
    sym = symtab_data->d_buf + i * sizeof(*sym);
    name = elf_strptr(target->elf, target->strtab_shidx, sym->st_name);

    if (strcmp(name, "module") != 0) {
      continue;
    }

    sym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    sym->st_other = STV_DEFAULT;
    sym->st_shndx = target->text_sh_idx;
    sym->st_value = 0;
    sym->st_size = image_size;

    elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);

    break;
  }

  elf_update(target->elf, ELF_C_WRITE);

  return 0;
}

static int
get_target_image(struct target_elf *target,
    uint8_t **imagep, size_t *image_sizep)
{
  uint8_t *image;
  size_t image_size;

  fseek(target->fp, 0, SEEK_END);
  image_size = ftell(target->fp);
  fseek(target->fp, 0, SEEK_SET);

  image = calloc(1, image_size);
  if (image == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  if (fread(image, image_size, 1, target->fp) != 1) {
    fprintf(stderr, "Failed to read raw ELF image from file\n");
    return -1;
  }

  *imagep = image;
  *image_sizep = image_size;

  return 0;
}

/*
 * Create an ELF image to load linked together with module ELF if provided
 */
static int
create_elf_image(uint8_t **target_imagep, size_t *target_image_sizep,
    uint8_t *module_image, size_t module_image_size)
{
  int error;
  struct target_elf *target;
  struct module_elf *module;

  error = open_target_elf(ipft_bpf_o, ipft_bpf_o_len, &target);
  if (error != 0) {
    fprintf(stderr, "open_target_elf failed\n");
    return -1;
  }

  if (module_image != NULL) {
    error = open_module_elf(module_image, module_image_size, &module);
    if (error != 0) {
      fprintf(stderr, "Failed to parse module ELF\n");
      return -1;
    }
  } else {
    module = NULL;
  }

  error = do_link(target, module);
  if (error != 0) {
    fprintf(stderr, "Failed to link module\n");
    return -1;
  }

  error = get_target_image(target, target_imagep, target_image_sizep);
  if (error != 0) {
    fprintf(stderr, "Failed to get target image\n");
    return -1;
  }

  close_target_elf(target);

  if (module_image != NULL) {
    close_module_elf(module);
  }

  return 0;
}

static struct {
  size_t total;
  size_t succeeded;
  size_t failed;
  size_t filtered;
  size_t untraceable;
} attach_stat;

static int
attach_cb(const char *sym, struct ipft_syminfo *si, void *data)
{
  struct bpf_link *link;
  struct bpf_program *prog;
  struct ipft_tracer *t = (struct ipft_tracer *)data;

  if (!traceable_set_is_traceable(t->tset, sym)) {
    attach_stat.untraceable++;
    return 0;
  }

  if (!regex_match(t->re, sym)) {
    attach_stat.filtered++;
    return 0;
  }

  switch (si->skb_pos) {
  case 1:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main1");
    break;
  case 2:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main2");
    break;
  case 3:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main3");
    break;
  case 4:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main4");
    break;
  case 5:
    prog = bpf_object__find_program_by_title(t->bpf, "kprobe/ipft_main5");
    break;
  default:
    fprintf(stderr, "Unsupported skb_pos %d\n", si->skb_pos);
    break;
  }

  link = bpf_program__attach_kprobe(prog, false, sym);
  if (link == NULL) {
    attach_stat.failed++;
    fprintf(stderr, "Attach kprobe failed for %s\n", sym);
    return -1;
  }

  attach_stat.succeeded++;

  fprintf(stderr,
          "\rAttaching program (total %zu, succeeded %zu, failed %zu filtered: "
          "%zu untraceable: %zu)",
          attach_stat.total, attach_stat.succeeded, attach_stat.failed,
          attach_stat.filtered, attach_stat.untraceable);
  fflush(stderr);

  return 0;
}

static int
attach_all(struct ipft_tracer *t)
{
  int error;
  attach_stat.total = symsdb_get_sym2info_total(t->sdb);
  error = symsdb_sym2info_foreach(t->sdb, attach_cb, t);
  fprintf(stderr, "\n");
  return error;
}

struct perf_sample_data {
  struct perf_event_header header;
  uint32_t size;
  uint8_t data[0];
};

static enum bpf_perf_event_ret
trace_cb(void *ctx, __unused int cpu, struct perf_event_header *ehdr)
{
  int error;
  struct ipft_tracer *t = (struct ipft_tracer *)ctx;
  struct perf_sample_data *s = (struct perf_sample_data *)ehdr;

  switch (ehdr->type) {
  case PERF_RECORD_SAMPLE:
    error = output_on_trace(t->out, (struct ipft_trace *)s->data);
    if (error == -1) {
      return LIBBPF_PERF_EVENT_ERROR;
    }
    break;
  case PERF_RECORD_LOST:
    break;
  default:
    return LIBBPF_PERF_EVENT_ERROR;
  }

  return LIBBPF_PERF_EVENT_CONT;
}

static int
perf_buffer_create(struct perf_buffer **pbp, struct ipft_tracer *t,
    size_t perf_page_cnt)
{
  struct perf_buffer *pb;
  struct perf_event_attr pe_attr = {0};
  struct perf_buffer_raw_opts pb_opts = {0};

  pe_attr.type = PERF_TYPE_SOFTWARE;
  pe_attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  pe_attr.sample_period = 1;
  pe_attr.sample_type = PERF_SAMPLE_RAW;
  pe_attr.wakeup_events = 1;

  pb_opts.attr = &pe_attr;
  pb_opts.event_cb = trace_cb;
  pb_opts.ctx = t;
  pb_opts.cpu_cnt = 0;

  pb = perf_buffer__new_raw(
      bpf_object__find_map_fd_by_name(t->bpf, "events"),
      perf_page_cnt, &pb_opts
  );
  if (pb == NULL) {
    fprintf(stderr, "perf_buffer__new_raw failed\n");
    return -1;
  }

  *pbp = pb;

  return 0;
}

static int
bpf_create(struct bpf_object **bpfp, uint32_t mark,
    uint32_t mask, struct ipft_script *script)
{
  int error;
  struct bpf_object *bpf;
  struct ipft_trace_config conf;
  uint8_t *target_image, *module_image;
  size_t target_image_size, module_image_size;

  struct bpf_object_open_opts opts = {
    .sz = sizeof(opts),
    .object_name = "ipft",
  };

  if (script != NULL) {
    error = script_exec_emit(script, &module_image, &module_image_size);
    if (error != 0) {
      fprintf(stderr, "script_exec_emit failed\n");
      return -1;
    }
  } else {
    module_image = NULL;
    module_image_size = 0;
  }

  error = create_elf_image(&target_image, &target_image_size,
      module_image, module_image_size);
  if (error != 0) {
    fprintf(stderr, "create_elf_image failed\n");
    return -1;
  }

  bpf = bpf_object__open_mem(target_image, target_image_size, &opts);
  if (bpf == NULL) {
    fprintf(stderr, "ipft_bpf__open_and_load failed\n");
    return -1;
  }

  error = bpf_object__load(bpf);
  if (error == -1) {
    fprintf(stderr, "bpf_object__load failed\n");
    return -1;
  }

  conf.mark = mark;
  conf.mask = mask;

  error = bpf_map_update_elem(
      bpf_object__find_map_fd_by_name(bpf, "config"),
      &(int){0}, &conf, 0
  );
  if (error == -1) {
    fprintf(stderr, "Cannot update config map\n");
    return -1;
  }

  *bpfp = bpf;

  return 0;
}

static int
tracer_create(struct ipft_tracer **tp, struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_tracer *t;

  t = calloc(1, sizeof(*t));
  if (t == NULL) {
    fprintf(stderr, "Failed to allocate memory\n");
    return -1;
  }

  error = symsdb_create(&t->sdb);
  if (error != 0) {
    fprintf(stderr, "symsdb_create failed\n");
    return -1;
  }

  error = debuginfo_create(&t->dinfo);
  if (error != 0) {
    fprintf(stderr, "debuginfo_create failed\n");
    return -1;
  }

  error = debuginfo_fill_sym2info(t->dinfo, t->sdb);
  if (error != 0) {
    fprintf(stderr, "debuginfo_fill_sym2info failed\n");
    return -1;
  }

  error = kallsyms_fill_addr2sym(t->sdb);
  if (error != 0) {
    fprintf(stderr, "kallsyms_fill_addr2sym failed\n");
    return -1;
  }

  if (opt->set_rlimit) {
    error = set_rlimit(t->sdb);
    if (error == -1) {
      fprintf(stderr, "set_rlimit failed\n");
      return -1;
    }
  }

  error = script_create(&t->script, opt->script);
  if (error == -1) {
    fprintf(stderr, "script_create failed\n");
    return -1;
  }

  error = bpf_create(&t->bpf, opt->mark, opt->mask, t->script);
  if (error == -1) {
    fprintf(stderr, "bpf_create failed\n");
    return -1;
  }

  error = regex_create(&t->re, opt->regex);
  if (error != 0) {
    fprintf(stderr, "regex_create failed\n");
    return -1;
  }

  error = traceable_set_create(&t->tset);
  if (error != 0) {
    fprintf(stderr, "tracable_set_create\n");
    return -1;
  }

  error = tracedb_create(&t->tdb);
  if (error != 0) {
    fprintf(stderr, "tracedb_create failed\n");
    return -1;
  }

  error = output_create(&t->out, opt->output_type, t->sdb, t->script);
  if (error != 0) {
    fprintf(stderr, "output_create failed\n");
    return -1;
  }

  error = perf_buffer_create(&t->pb, t, opt->perf_page_cnt);
  if (error == -1) {
    fprintf(stderr, "perf_buffer_create failed\n");
    return -1;
  }

  *tp = t;

  return 0;
}

static bool end = false;

static void
handle_sigint(__unused int signum)
{
  end = true;
  signal(SIGINT, SIG_DFL);
}

static int
do_trace(struct ipft_tracer *t)
{
  int error;

  signal(SIGINT, handle_sigint);

  while (!end) {
    if ((error = perf_buffer__poll(t->pb, 1000)) < 0) {
      /* perf_buffer__poll cancelled with SIGINT */
      if (end) {
        break;
      }
      return -1;
    }
  }

  error = output_post_trace(t->out);
  if (error == -1) {
    fprintf(stderr, "output_post_trace failed\n");
    return -1;
  }

  return 0;
}

int
tracer_run(struct ipft_tracer_opt *opt)
{
  int error;
  struct ipft_tracer *t;

  error = tracer_create(&t, opt);
  if (error == -1) {
    fprintf(stderr, "tracer_create failed\n");
    return -1;
  }

  error = attach_all(t);
  if (error) {
    fprintf(stderr, "attach_all failed\n");
    return -1;
  }

  fprintf(stderr, "Trace ready!\n");

  return do_trace(t);
}
