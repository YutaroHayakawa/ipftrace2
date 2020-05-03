#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <linux/version.h>
#include <linux/types.h>

#include "bpf.h"
#include "ipftrace.h"

/*
 * Architecture dependent parameters
 */
#ifdef __x86_64__
/*
 * PT_REGS_IP(regs)
 */
static const uint32_t pt_regs_ip_offset = offsetof(struct pt_regs, rip);
/*
 * PT_REGS_PARAM[1-5], indexed by parameter position
 */
static uint32_t pt_regs_param_offset[] = {
  offsetof(struct pt_regs, rdi),
  offsetof(struct pt_regs, rsi),
  offsetof(struct pt_regs, rdx),
  offsetof(struct pt_regs, rcx),
  offsetof(struct pt_regs, r8)
};
#else
#error Unsupported architecture
#endif

/*
 * Leave r10 - MODULE_STACK_SIZE of stack space for module.
 * Put struct ipft_trace on top of it.
 */
#define MODULE_STACK_SIZE 256

/*
 * Cast to satisfy the compiler
 */
#define TRACE_OFFSET (-(int32_t)(MODULE_STACK_SIZE + sizeof(struct ipft_trace)))

/*
 * License
 */
#define LICENSE "Dual BSD/GPL"

/*
 * Max skb position in the function parameters
 */
#define MAX_SKB_POS 5

struct ipft_bpf_prog {
  int perf_map_fd;
  struct {
    struct bpf_insn *insns;
    uint32_t insns_cnt;
    int fd;
  } progs[MAX_SKB_POS];
};

static int
bpf(enum bpf_cmd cmd, union bpf_attr *attr, size_t size)
{
  return syscall(__NR_bpf, cmd, attr, size);
}

static int
gen_program(int skb_pos, uint32_t mark, ptrdiff_t mark_offset,
    struct bpf_insn *mod, uint32_t mod_cnt, int perf_map_fd,
    struct bpf_insn **insnp, uint32_t *insn_cnt)
{
  struct bpf_insn bottom_half[] = {
    /*
     * bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU,
     *                       &trace, sizeof(trace));
     */
    BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, TRACE_OFFSET),
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_6),
    BPF_LD_MAP_FD(BPF_REG_2, perf_map_fd),
    BPF_MOV64_IMM(BPF_REG_3, BPF_F_CURRENT_CPU),
    BPF_MOV64_IMM(BPF_REG_5, (uint32_t)sizeof(struct ipft_trace)),
    BPF_CALL_INSN(BPF_FUNC_perf_event_output),
    BPF_EXIT_INSN(),
  };

  uint32_t bottom_half_cnt = sizeof(bottom_half) / sizeof(bottom_half[0]);

  struct bpf_insn top_half[] = {
    /* Save ctx for future use */
    BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
    /* skb = PT_REGS_PARAM1(ctx) */
    BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, pt_regs_param_offset[skb_pos - 1]),
    /* bpf_probe_read(&mark, 4, skb + mark_offset) */
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -4),
    BPF_MOV64_IMM(BPF_REG_2, 4),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_7),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, mark_offset),
    BPF_CALL_INSN(BPF_FUNC_probe_read),
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
    BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_10, -4),
    /* if (mark != target_mark) goto end; */
    BPF_JMP32_IMM(BPF_JNE, BPF_REG_8, mark, 23 + mod_cnt + bottom_half_cnt - 1),
    /* trace->skb_addr = skb */
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, TRACE_OFFSET),
    /* trace->tstamp = bpf_ktime_get_ns(); */
    BPF_CALL_INSN(BPF_FUNC_ktime_get_ns),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, TRACE_OFFSET + 8),
    /* trace->faddr = PT_REGS_IP(ctx) */
    BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_6, pt_regs_ip_offset),
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, TRACE_OFFSET + 16),
    /* trace->processor_id = bpf_get_smp_processor_id(); */
    BPF_CALL_INSN(BPF_FUNC_get_smp_processor_id),
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, TRACE_OFFSET + 24),
    /* zero clear the trace->_pad to satisfy the verifier */
    BPF_ST_MEM(BPF_W, BPF_REG_10, TRACE_OFFSET + 28, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_10, TRACE_OFFSET + 32, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_10, TRACE_OFFSET + 40, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_10, TRACE_OFFSET + 48, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_10, TRACE_OFFSET + 56, 0),
    /* zero clear the trace->data to satisfy the verifier */
    BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, TRACE_OFFSET + (int32_t)offsetof(struct ipft_trace, data)),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 0, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 8, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 16, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 24, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 32, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 40, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 48, 0),
    BPF_ST_MEM(BPF_DW, BPF_REG_1, 56, 0),
    BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
    BPF_MOV64_REG(BPF_REG_3, BPF_REG_7),
    /* 
     * Module code comes to here
     * REG1 = trace->data
     * REG2 = ctx
     * REG3 = skb
     */
  };

  uint32_t top_half_cnt = sizeof(top_half) / sizeof(top_half[0]);

  *insnp = calloc(top_half_cnt + mod_cnt + bottom_half_cnt, sizeof(top_half[0]));
  if (*insnp == NULL) {
    return -1;
  }

  *insn_cnt = top_half_cnt + mod_cnt + bottom_half_cnt;

  memcpy(*insnp, top_half, top_half_cnt * sizeof(top_half[0]));
  memcpy(*insnp + top_half_cnt, mod, mod_cnt * sizeof(mod[0]));
  memcpy(*insnp + top_half_cnt + mod_cnt, bottom_half,
	  bottom_half_cnt * sizeof(bottom_half[0]));

  return 0;
}

static uint32_t
get_kernel_version(void)
{
  uint32_t major, minor, patch;
  struct utsname info;

  uname(&info);
  if (sscanf(info.release, "%u.%u.%u", &major, &minor, &patch) != 3) {
    return 0;
  }

  return KERNEL_VERSION(major, minor, patch);
}

static int
create_perf_map(void)
{
  long ncpus;
  union bpf_attr attr = {};

  ncpus = sysconf(_SC_NPROCESSORS_CONF);

  attr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
  attr.key_size = sizeof(uint32_t);
  attr.value_size = sizeof(uint32_t);
  attr.max_entries = ncpus;

  return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

#define LOGBUF_SIZE 0xffff

static int
load_program(uint32_t mark, ptrdiff_t mark_offset,
             struct bpf_insn *mod, uint32_t mod_cnt,
             int perf_map_fd, struct ipft_bpf_prog *prog)
{
  char *log_buf;
  int i, fd, error;
  uint32_t insns_cnt;
  struct bpf_insn *insns;
  union bpf_attr attr = {};

  /*
   * Take larger buffer
   */
  log_buf = calloc(1, LOGBUF_SIZE);
  if (log_buf == NULL) {
    perror("calloc");
    return -1;
  }

  attr.prog_type = BPF_PROG_TYPE_KPROBE;
  attr.license = (uint64_t)LICENSE;
  attr.log_level = (1 | 2 | 4);
  attr.log_size = LOGBUF_SIZE;
  attr.log_buf = (uint64_t)log_buf;
  attr.kern_version = get_kernel_version();

  for (i = 0; i < MAX_SKB_POS; i++) {
    error = gen_program(i + 1, mark, mark_offset, mod, mod_cnt,
        perf_map_fd, &insns, &insns_cnt);
    if (error == -1) {
      goto err0;
    }

    memset(log_buf, 0, LOGBUF_SIZE);

    attr.insn_cnt = insns_cnt;
    attr.insns = (uint64_t)insns;

    fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
      switch (errno) {
        case EPERM:
          fprintf(stderr, "%s\n", log_buf);
          break;
        default:
          perror("bpf");
          fprintf(stderr, "%s\n", log_buf);
          break;
      }
      goto err0;
    }

    prog->progs[i].insns = insns;
    prog->progs[i].insns_cnt = insns_cnt;
    prog->progs[i].fd = fd;
  }

  free(log_buf);

  return 0;

err0:
  for (i = i - 1; i > 0; i--) {
    free(prog->progs[i].insns);
    close(prog->progs[i].fd);
  }

  free(log_buf);

  return -1;
}

static void
unload_program(struct ipft_bpf_prog *prog)
{
  for (int i = 0; i < MAX_SKB_POS; i++) {
    free(prog->progs[i].insns);
    close(prog->progs[i].fd);
  }
}

static void
detach_perf_buffer(struct ipft_bpf_prog *prog)
{
  int error;
  union bpf_attr attr = {};

  attr.map_fd = prog->perf_map_fd;
  attr.flags = 0;

  for (long i = 0; i < ncpus = sysconf(_SC_NPROCESSORS_CONF); i++) {
    attr.key = (__u64)&(int){i};
    error = bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
    assert(error == 0);
  }
}

int
bpf_prog_get(struct ipft_bpf_prog *prog, int skb_pos)
{
  assert(skb_pos <= MAX_SKB_POS);
  return prog->progs[skb_pos - 1].fd;
}

int
bpf_prog_load(struct ipft_bpf_prog **progp, uint32_t mark,
                   size_t mark_offset, struct bpf_insn *mod,
                   uint32_t mod_cnt)
{
  int error, perf_map_fd;
  struct ipft_bpf_prog *prog;

  prog = calloc(1, sizeof(*prog));
  if (prog == NULL) {
    perror("calloc");
    return -1;
  }

  perf_map_fd = create_perf_map();
  if (perf_map_fd < 0) {
    perror("bpf(BPF_MAP_CREATE)");
    goto err0;
  }

  prog->perf_map_fd = perf_map_fd;

  error = load_program(mark, mark_offset, mod,
      mod_cnt, perf_map_fd, prog);
  if (error == -1) {
    goto err1;
  }

  *progp = prog;

  return 0;

err1:
  free(*progp);
err0:
  close(perf_map_fd);
  return -1;
}

int
bpf_prog_set_perf_fd(struct ipft_bpf_prog *prog, int perf_fd)
{
  int error;
  long i, ncpus;
  union bpf_attr attr = {};

  ncpus = sysconf(_SC_NPROCESSORS_CONF);

  attr.map_fd = prog->perf_map_fd;
  attr.value = (__u64)&(int){fd};
  attr.flags = 0;

  for (i = 0; i < ncpus; i++) {
    attr.key = (__u64)&(int){i};
    error = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
    if (error == -1) {
      goto end;
    }
  }

  return 0;

end:
  memset(&attr, 0, sizeof(attr));
  for (i = i - 1; i > 0; i--) {
    attr.key = (__u64)&(int){i};
    error = bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
    assert(error == 0);
  }
  return -1;
}

void
bpf_prog_unload(struct ipft_bpf_prog *prog)
{
  unload_program(prog);
  detach_perf_buffer(prog);
  close(prog->perf_map_fd);
  free(prog);
}
