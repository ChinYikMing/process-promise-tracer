#include "list.h"
#include "process.h" 
#include "basis.h" 
#include "signal.h"
#include "config.h"
#include "cpu.h"
#include "log.h"

int main(int argc, char **argv){
	if(argc == 2 && strcmp(argv[1], "-c") == 0) // co-operate with systemd service file
		exit(config_parse(CONFIG_FILE));

	config_init(&cf);
	config_read(cf);

	cpu_init(&cpu);
	cpu_stat(cpu);

	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sighup_handler;
	sigaction(SIGHUP, &sa, NULL);

	self_pid = getpid();
	sprintf(self_name, "%d", self_pid);

	List *proc_list = malloc(sizeof(List));
	LIST_INIT(proc_list);

	while(1){
		sleep(1);

		if(sighup_coming){
			sighup_coming = 0;
			config_read(cf);
			cpu_stat(cpu);
			printf("received signal!\n");
		}

		scan_proc_dir(proc_list, PROC_DIR, NULL, 0.5);
		size_t proc_list_size = list_size(proc_list);
		printf("process count: %zu\n", proc_list_size);
	}
	return 0;
}
