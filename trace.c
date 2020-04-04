#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "ipftrace.elf.h"
#include "ipftrace.h"
#include "klist.h"

struct attach_ctx {
  int verbose;
  size_t total;
  size_t attached;
  size_t failed;
  struct bpf_object *bpf;
  struct bpf_program *main1;
  struct bpf_program *main2;
  struct bpf_program *main3;
  struct bpf_program *main4;
  struct ipft_symsdb *sdb;
};

struct trace_ctx {
  struct ipft_tracedb *tdb;
};

#define ERROR_BUF_SIZE 256

static bool trace_finish = false;
static char error_buf[ERROR_BUF_SIZE] = {};

static void links_dtor(void *priv) {
  bpf_link__destroy(*(struct bpf_link **)priv);
}

KLIST_INIT(links, struct bpf_link *, links_dtor)

struct bpf_prog_priv {
  struct bpf_insn *prog;
  klist_t(links) * links;
};

static int bpf_prog_priv_create(struct bpf_prog_priv **privp) {
  struct bpf_prog_priv *priv;

  priv = (struct bpf_prog_priv *)malloc(sizeof(*priv));
  if (priv == NULL) {
    perror("malloc");
    return -1;
  }

  priv->prog = NULL;

  priv->links = kl_init(links);
  if (priv->links == NULL) {
    perror("kl_init");
    goto err0;
  }

  *privp = priv;

  return 0;

err0:
  free(priv);
  return -1;
}

static void bpf_prog_priv_destroy(struct bpf_prog_priv *priv) {
  if (priv->prog != NULL) {
    free(priv->prog);
  }
  kl_destroy(links, priv->links);
  free(priv);
}

static void bpf_prog_priv_dtor(__unused struct bpf_program *prog, void *_priv) {
  struct bpf_prog_priv *priv = (struct bpf_prog_priv *)_priv;
  bpf_prog_priv_destroy(priv);
}

static int pr_suppress_warn(enum libbpf_print_level level, const char *format,
                            va_list args) {
  if (level == LIBBPF_WARN) {
    return 0;
  }
  return vfprintf(stderr, format, args);
}

static void on_sigint(__unused int sig) { trace_finish = true; }

static void on_event(void *_ctx, __unused int cpu, void *data,
                     __unused __u32 size) {
  int error;
  struct ipft_trace *trace;
  struct trace_ctx *ctx;

  ctx = (struct trace_ctx *)_ctx;

  trace = (struct ipft_trace *)malloc(sizeof(*trace));
  if (trace == NULL) {
    perror("malloc");
    trace_finish = true;
    return;
  }

  memcpy(trace, data, sizeof(*trace));

  error = tracedb_put_trace(ctx->tdb, trace);
  if (error == -1) {
    fprintf(stderr, "Failed to add trace: %s\n", strerror(error));
  }

  printf("Captured %zu sk_buffs\r", tracedb_get_total(ctx->tdb));
}

static void on_lost(__unused void *ctx, __unused int cpu, __u64 cnt) {
  fprintf(stderr, "%llu events lost\n", cnt);
}

static int attach_kprobe(const char *sym, struct ipft_syminfo *si, void *arg) {
  struct bpf_link *link;
  struct bpf_prog_priv *priv;
  struct attach_ctx *ctx;
  libbpf_print_fn_t orig_fn;
  struct bpf_program *main_prog;

  ctx = (struct attach_ctx *)arg;

  if (ctx->verbose <= IPFT_LOG_WARN) {
    orig_fn = libbpf_set_print(pr_suppress_warn);
  } else {
    orig_fn = NULL;
  }

  switch (si->skb_pos) {
  case 1:
    main_prog = ctx->main1;
    break;
  case 2:
    main_prog = ctx->main2;
    break;
  case 3:
    main_prog = ctx->main3;
    break;
  case 4:
    main_prog = ctx->main4;
    break;
  default:
    fprintf(stderr, "Invalid skb position\n");
    return -1;
  }

  link = bpf_program__attach_kprobe(main_prog, false, sym);
  if (libbpf_get_error(link) == 0) {
    ctx->attached++;
    priv = bpf_program__priv(main_prog);
    *kl_pushp(links, priv->links) = link;
  } else {
    ctx->failed++;
  }

  printf("Attaching %zu probes (Attached: %zu Failed: %zu)\r", ctx->total,
         ctx->attached, ctx->failed);

  if (orig_fn != NULL) {
    libbpf_set_print(orig_fn);
  }

  return 0;
}

static int prog_preprocess(__unused struct bpf_program *prog, __unused int n,
                           struct bpf_insn *insns, int insns_cnt,
                           struct bpf_prog_prep_result *res) {
  struct bpf_prog_priv *priv;
  int patch_len, offset = -1;
  struct bpf_insn *p, *patch = NULL;
  struct bpf_insn patch_default[] = {{BPF_JMP | BPF_JA, 0, 0, 0, 0}};

  // TODO Put module hook to here

  if (patch == NULL) {
    patch = patch_default;
    patch_len = sizeof(patch_default) / sizeof(*patch);
  }

  p = calloc(insns_cnt + patch_len, sizeof(*p));
  if (p == NULL) {
    return -1;
  }

  res->new_insn_ptr = p;
  res->new_insn_cnt = insns_cnt + patch_len - 1;
  res->pfd = NULL;

  for (int i = 0; i < insns_cnt; i++) {
    if (insns[i].code == (BPF_JMP | BPF_CALL) &&
        insns[i].imm == IPFT_DUMMY_HELPER_ID) {
      offset = i;
    }
  }

  if (offset == -1) {
    fprintf(stderr, "Failed to find BPF module callsite\n");
    return -1;
  }

  memcpy(p, insns, offset * sizeof(*p));
  memcpy(p + offset, patch, patch_len * sizeof(*p));
  memcpy(p + offset + patch_len, insns + offset + 1,
         (insns_cnt - offset - 1) * sizeof(*p));

  priv = bpf_program__priv(prog);
  priv->prog = p;

  return 0;
}

#define bpf_object_find_main(_bpf, _x)                                         \
  do {                                                                         \
    main##_x = bpf_object__find_program_by_name(bpf, "ipftrace_main" #_x);     \
    if ((error = libbpf_get_error(main##_x)) != 0) {                           \
      libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);                       \
      fprintf(stderr, "bpf_object__find_program_by_title: %s\n", error_buf);   \
      return -1;                                                               \
    }                                                                          \
  } while (0)

#define bpf_object_find_all_main(_bpf)                                         \
  do {                                                                         \
    bpf_object_find_main(_bpf, 1);                                             \
    bpf_object_find_main(_bpf, 2);                                             \
    bpf_object_find_main(_bpf, 3);                                             \
    bpf_object_find_main(_bpf, 4);                                             \
  } while (0)

#define bpf_object_set_prep_to_main(_bpf, _f, _x)                              \
  do {                                                                         \
    error = bpf_program__set_prep(main##_x, 1, _f);                            \
    if (error != 0) {                                                          \
      libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);                       \
      fprintf(stderr, "bpf_program__set_prep: %s\n", error_buf);               \
      return -1;                                                               \
    }                                                                          \
  } while (0)

#define bpf_object_set_prep_to_all_main(_bpf, _f)                              \
  do {                                                                         \
    bpf_object_set_prep_to_main(_bpf, _f, 1);                                  \
    bpf_object_set_prep_to_main(_bpf, _f, 2);                                  \
    bpf_object_set_prep_to_main(_bpf, _f, 3);                                  \
    bpf_object_set_prep_to_main(_bpf, _f, 4);                                  \
  } while (0)

static int bpf_object_set_preps(struct bpf_object *bpf) {
  int error;
  struct bpf_program *main1, *main2, *main3, *main4;

  bpf_object_find_all_main(bpf);
  bpf_object_set_prep_to_all_main(bpf, prog_preprocess);

  return 0;
}

#define bpf_object_set_priv_to_main(_f, _priv, _dtor)                          \
  do {                                                                         \
    error = bpf_prog_priv_create(&priv);                                       \
    if (error == -1) {                                                         \
      fprintf(stderr, "Failed to create bpf_prog_priv\n");                     \
      return -1;                                                               \
    }                                                                          \
    bpf_program__set_priv(_f, _priv, _dtor);                                   \
  } while (0)

#define bpf_object_set_priv_to_all_main(_priv, _dtor)                          \
  do {                                                                         \
    bpf_object_set_priv_to_main(main1, _priv, _dtor);                          \
    bpf_object_set_priv_to_main(main2, _priv, _dtor);                          \
    bpf_object_set_priv_to_main(main3, _priv, _dtor);                          \
    bpf_object_set_priv_to_main(main4, _priv, _dtor);                          \
  } while (0)

static int bpf_object_set_privs(struct bpf_object *bpf) {
  int error;
  struct bpf_prog_priv *priv;
  struct bpf_program *main1, *main2, *main3, *main4;

  bpf_object_find_all_main(bpf);
  bpf_object_set_priv_to_all_main(priv, bpf_prog_priv_dtor);

  return 0;
}

static struct bpf_object *bpf_object_open_and_load(unsigned char *buf,
                                                   size_t len) {
  int error;
  struct bpf_object *bpf;

  bpf = bpf_object__open_buffer(buf, len, "ipftrace2");
  if ((error = libbpf_get_error(bpf)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__open_mem: %s\n", error_buf);
    return NULL;
  }

  error = bpf_object_set_preps(bpf);
  if (error == -1) {
    fprintf(stderr, "Failed to set BPF preprocessor\n");
    goto err0;
  }

  error = bpf_object_set_privs(bpf);
  if (error == -1) {
    fprintf(stderr, "Failed to set BPF private data\n");
    goto err0;
  }

  error = bpf_object__load(bpf);
  if (error != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__load: %s\n", error_buf);
    goto err0;
  }

  return bpf;

err0:
  bpf_object__close(bpf);
  return NULL;
}

static int set_ctrl_data(struct bpf_object *bpf, uint32_t mark,
                         uint32_t mark_offset) {
  int error, fd;
  struct ipft_ctrl_data cdata;

  fd = bpf_object__find_map_fd_by_name(bpf, "ctrl_map");
  if (fd < 0) {
    libbpf_strerror(-fd, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_map_by_name: %s\n", error_buf);
    return -1;
  }

  cdata.mark = mark;
  cdata.mark_offset = mark_offset;

  error = bpf_map_update_elem(fd, &(int){0}, &cdata, BPF_ANY);
  if (error != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_map_update_elem: %s\n", error_buf);
    return -1;
  }

  return 0;
}

static int attach_probes(struct bpf_object *bpf, struct ipft_symsdb *sdb,
                         int verbose) {
  int error;
  struct attach_ctx ctx;
  struct bpf_program *main1, *main2, *main3, *main4;

  ctx.verbose = verbose;
  ctx.bpf = bpf;
  ctx.total = symsdb_get_sym2info_total(sdb);
  ctx.attached = 0;
  ctx.failed = 0;

  bpf_object_find_all_main(bpf);

  ctx.main1 = main1;
  ctx.main2 = main2;
  ctx.main3 = main3;
  ctx.main4 = main4;

  error = symsdb_sym2info_foreach(sdb, attach_kprobe, &ctx);
  if (error != 0) {
    fprintf(stderr, "Failed to attach kprobe\n");
    return -1;
  }

  printf("\n");

  return 0;
}

static int run_trace(struct bpf_object *bpf, struct ipft_tracedb *tdb) {
  int error, fd;
  struct trace_ctx ctx;
  struct perf_buffer *pb;
  struct perf_buffer_opts pb_opts;

  fd = bpf_object__find_map_fd_by_name(bpf, "events");
  if (fd < 0) {
    libbpf_strerror(-fd, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "bpf_object__find_map_by_name: %s\n", error_buf);
    return -1;
  }

  ctx.tdb = tdb;

  pb_opts.sample_cb = on_event;
  pb_opts.lost_cb = on_lost;
  pb_opts.ctx = &ctx;

  signal(SIGINT, on_sigint);

  pb = perf_buffer__new(fd, 64, &pb_opts);
  if ((error = libbpf_get_error(pb)) != 0) {
    libbpf_strerror(error, error_buf, ERROR_BUF_SIZE);
    fprintf(stderr, "perf_buffer__new: %s\n", error_buf);
    return -1;
  }

  while ((error = perf_buffer__poll(pb, 100)) >= 0) {
    if (trace_finish) {
      break;
    }
  }

  printf("\n");

  perf_buffer__free(pb);

  return 0;
}

static int debuginfo_create(struct ipft_debuginfo **dinfo,
                            struct ipft_opt *opt) {
  if (strcmp(opt->debug_format, "dwarf") == 0) {
    return dwarf_debuginfo_create(dinfo);
  }

  if (strcmp(opt->debug_format, "btf") == 0) {
    return btf_debuginfo_create(dinfo);
  }

  return -1;
}

void do_trace(struct ipft_opt *opt) {
  int error;
  struct bpf_object *bpf;
  struct ipft_symsdb *sdb;
  struct ipft_tracedb *tdb;
  struct ipft_debuginfo *dinfo;

  error = symsdb_create(&sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to create symsdb\n");
    return;
  }

  error = tracedb_create(&tdb);
  if (error == -1) {
    fprintf(stderr, "Failed to create tracedb\n");
    goto err0;
  }

  error = debuginfo_create(&dinfo, opt);
  if (error == -1) {
    fprintf(stderr, "Failed to create debuginfo\n");
    goto err1;
  }

  error = debuginfo_fill_sym2info(dinfo, sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to fill sym2info\n");
    goto err2;
  }

  error = kallsyms_fill_addr2sym(sdb);
  if (error == -1) {
    fprintf(stderr, "Failed to fill addr2sym\n");
    goto err2;
  }

  bpf = bpf_object_open_and_load(ipftrace_bpf_o, ipftrace_bpf_o_len);
  if (bpf == NULL) {
    fprintf(stderr, "Failed to open and load BPF object\n");
    goto err2;
  }

  error = set_ctrl_data(bpf, opt->mark, symsdb_get_mark_offset(sdb));
  if (error == -1) {
    fprintf(stderr, "Failed to set BPF control data\n");
    goto err3;
  }

  error = attach_probes(bpf, sdb, opt->verbose);
  if (error == -1) {
    fprintf(stderr, "Failed to attach probes\n");
    goto err3;
  }

  error = run_trace(bpf, tdb);
  if (error == -1) {
    fprintf(stderr, "Error occured while running the trace\n");
    goto err3;
  }

  tracedb_dump(tdb, sdb, stdout);

err3:
  bpf_object__close(bpf);
err2:
  debuginfo_destroy(dinfo);
err1:
  tracedb_destroy(tdb);
err0:
  symsdb_destroy(sdb);
  return;
}
