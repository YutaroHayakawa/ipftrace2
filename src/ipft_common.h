#pragma once
#include <stdint.h>

struct ipft_trace_config {
  uint32_t mark;
  uint32_t mask;
};

struct ipft_event {
  uint64_t packet_id;
  uint64_t tstamp;
  uint64_t faddr;
  uint32_t processor_id;
  uint8_t is_return;
  uint8_t _pad[35]; // for future use
  uint8_t data[64];
  /* 128Bytes */
} __attribute__((aligned(8)));
