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
	if(!proc_list){
		log_open();
		syslog(LOG_ERR, LOG_PREFIX"process list malloc failed");
		log_close();

		exit(EXIT_FAILURE);
	}
	LIST_INIT(proc_list);

	int scan_procfs_period; 
	Node *iter;
	Conf *c;
	LIST_FOR_EACH(cf->list, iter){
		c = LIST_ENTRY(iter, Conf);
		if(0 == strcmp(c->key, "scan_procfs_period")){
			sscanf(c->val, "%d", &scan_procfs_period);
			break;
		}
	}

	while(1){
		usleep(scan_procfs_period);
		cpu_stat(cpu);              // CPU clock speed changes with its temperature

		if(sighup_coming){
			sighup_coming = 0;
			config_read(cf);
			printf("received signal!\n");
		}

		scan_proc_dir(proc_list, PROC_DIR, NULL);
		size_t proc_list_size = list_size(proc_list);
		printf("process count: %zu\n", proc_list_size);
	}

	// never reach here
	exit(EXIT_SUCCESS);
}
