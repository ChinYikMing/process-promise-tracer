#ifndef CPU_HDR
#define CPU_HDR

#include "basis.h"
#include <sys/sysinfo.h>

#define CPUINFO_FILE "/proc/cpuinfo"

typedef struct cpu {
	unsigned long clock_speed;
} CPU;

extern CPU *cpu;

int cpu_init(CPU **cpu);
int cpu_stat(CPU *cpu);

#endif
