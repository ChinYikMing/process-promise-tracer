#ifndef PERF_VA_HDR
#define PERF_VA_HDR

#include <stdint.h>

typedef struct va_sample {
	uint32_t pid, tid;
	uint64_t buf_addr;
} va_sample_t;

#endif
