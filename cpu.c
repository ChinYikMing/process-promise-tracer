#include "cpu.h"

CPU *cpu = NULL;

int cpu_init(CPU **cpu){
	int cpu_cnt = get_nprocs();
	void *tmp = malloc(sizeof(CPU) * cpu_cnt);
	if(!tmp)
		handle_error("cpu init failed");

	*cpu = tmp;
	return 0;
}

int cpu_stat(CPU *cpu){
	int idx = 0;
	char *ptr;
	char buf[BUF_SIZE] = {0};
	FILE *cpu_file_ptr = fopen(CPUINFO_FILE, "r");
	if(!cpu_file_ptr)
		return 1;

	while(fgets(buf, BUF_SIZE, cpu_file_ptr)){
		if(strstr(buf, "MHz")){
			ptr = buf;
			ptr = strchr(ptr, ':') + 2;
			//printf("ptr: %s", ptr);
			sscanf(ptr, "%lu", &(cpu[idx].clock_speed));
			idx++;
		}
	}

	/*
	for(int i = 0; i < idx; i++){
		printf("cpu %d speed: %lu\n", i+1, cpu[i].clock_speed);
	}
	exit(1);
	*/

	fclose(cpu_file_ptr);
	return 0;
}
