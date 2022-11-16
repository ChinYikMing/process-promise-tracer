#ifndef PERF_TRACEPOINT_HDR
#define PERF_TRACEPOINT_HDR

typedef struct trp_sample {
	uint64_t ip;
        uint32_t pid, tid;
        uint64_t time;
        uint32_t cpu, res;
        uint64_t period;
        uint32_t size;
        char data[64];
} trp_sample_t;

#endif
