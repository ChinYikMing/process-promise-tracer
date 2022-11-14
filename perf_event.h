#ifndef PERF_EVENT_HDR
#define PERF_EVENT_HDR

typedef enum event {
	// RAW
	ALL_LOADS = 0x81D0,     
        ALL_STORES = 0x82D0,

	// Tracepoint, all available tracepoint in /sys/kernel/debug/tracing/events/x/x/id
	SYSCALL_WRITE = 694 // /sys/kernel/debug/tracing/events/syscall/sys_enter_write/id
} event_t;

#endif
