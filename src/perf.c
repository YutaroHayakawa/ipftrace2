#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "ipftrace.h"

struct ipft_perf_buffer {
  size_t page_cnt;
  size_t page_size;
  size_t mmap_size;
  int fd;
  uint8_t *base;
};

static int
perf_event_open(struct perf_event_attr *attr, pid_t pid,
    int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static inline uint64_t
ring_buffer_read_head(struct perf_event_mmap_page *base)
{
  uint64_t p = (*(volatile uint64_t *)&base->data_head);
  __sync_synchronize();
  return p;
}

static inline void
ring_buffer_write_tail(struct perf_event_mmap_page *base, uint64_t tail)
{
  __sync_synchronize();
  (*(volatile uint64_t *)&base->data_tail) = tail;
}

int
perf_buffer_get_fd(struct ipft_perf_buffer *pb)
{
  return pb->fd;
}

int
perf_event_process_mmap_page(struct ipft_perf_buffer *pb,
    int (*cb)(struct perf_event_header *, void *), void *data)
{
  int error;
  void *base;
  uint64_t data_head, data_tail;
  struct perf_event_header *ehdr;
  struct perf_event_mmap_page *header;

  header = (struct perf_event_mmap_page *)pb->base;
  base = pb->base + pb->page_size;
  data_head = ring_buffer_read_head(header);
  data_tail = header->data_tail;

  while (data_head != data_tail) {
    ehdr = base + (data_tail & (pb->mmap_size - 1));

    error = cb(ehdr, data);
    if (error == -1) {
      fprintf(stderr, "process_record failed\n");
      return -1;
    }

    data_tail += ehdr->size;
  }

  ring_buffer_write_tail(header, data_tail);

  return 0;
}

void
perf_buffer_destroy(struct ipft_perf_buffer *pb)
{
  munmap(pb->base, pb->page_cnt * pb->page_size); 
  close(pb->fd);
  free(pb);
}

int
perf_buffer_create(struct ipft_perf_buffer **pbp, size_t page_cnt)
{
  int error, fd;
  uint8_t *base;
  long page_size;
  struct ipft_perf_buffer *pb;
  struct perf_event_attr attr = {};

  if (page_cnt & (page_cnt - 1)) {
    fprintf(stderr, "Page count should be power of 2\n");
    return -1;
  }

  page_size = sysconf(_SC_PAGESIZE);

  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_BPF_OUTPUT;
  attr.sample_period = 1;
  /*
  attr.sample_type = PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR |
                     PERF_SAMPLE_CPU | PERF_SAMPLE_RAW;
  */
  attr.sample_type = PERF_SAMPLE_RAW;
  attr.wakeup_events = 1;

  pb = calloc(1, sizeof(*pb));
  if (pb == NULL) {
    perror("calloc");
    return -1;
  }

  fd = perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
  if (fd < 0) {
    perror("perf_event_open");
    goto err0;
  }

  base = mmap(NULL, page_size * (page_cnt + 1),
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (base == MAP_FAILED) {
    perror("mmap");
    goto err1;
  }

  error = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  if (error < 0) {
    perror("ioctl PERF_EVENT_IOC_ENABLE");
    goto err2;
  }

  pb->page_cnt = page_cnt;
  pb->page_size = page_size;
  pb->mmap_size = page_size * page_cnt;
  pb->fd = fd;
  pb->base = base;

  *pbp = pb;

  return 0;

err2:
  munmap(base, page_size * (page_cnt + 1));
err1:
  close(fd);
err0:
  free(pb);
  return -1;
}

static int get_kprobe_perf_type(void)
{
  FILE *f;
  int error, type;
  const char *file = "/sys/bus/event_source/devices/kprobe/type";

  f = fopen(file, "r");
  if (!f) {
    fprintf(stderr, "Failed to open %s: %s\n", file, strerror(errno));
    return -1;
  }

  error = fscanf(f, "%d\n", &type);
  if (error != 1) {
    type = -1;
    error = error == EOF ? EIO : errno;
    fprintf(stderr, "Failed to parse %s: %s\n", file, strerror(error));
    goto err0;
  }

err0:
  fclose(f);
  return type;
}

static int
perf_event_open_kprobe(const char *name)
{
  int pfd, type;
  struct perf_event_attr attr = {};

  type = get_kprobe_perf_type();
  if (type == -1) {
    fprintf(stderr, "Failed to get perf type\n");
    return -1;
  }

  attr.type = (uint32_t)type;
  attr.kprobe_func = (uint64_t)name;
  attr.probe_offset = 0;

  pfd = perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
  if (pfd == -1) {
    /*
     * Don't generate error in here, otherwise users will see
     * a lot of error message.
     */
    return -1;
  }

  return pfd;
}

int
perf_event_attach_kprobe(const char *name, int prog_fd)
{
  int error, pfd;

  pfd = perf_event_open_kprobe(name);
  if (pfd == -1) {
    /*
     * Don't generate error in here, otherwise users will see
     * a lot of error message.
     */
    return -1;
  }

  error = ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd);
  if (error == -1) {
    fprintf(stderr, "Failed to attach eBPF program to kprobe\n");
    goto err0;
  }

  error = ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
  if (error == -1) {
    fprintf(stderr, "Failed to enable kprobe\n");
    goto err0;
  }

  return pfd;

err0:
  close(pfd);
  return -1;
}
