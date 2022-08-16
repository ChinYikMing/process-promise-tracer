#include "list.h"
#include "process.h" 
#include "basis.h" 
#include "signal.h"
#include "config.h"

int main(int argc, char **argv){
	if(argc == 2 && strcmp(argv[1], "-c") == 0) // co-operate with systemd service file
		exit(config_parse(CONFIG_FILE));

	Config config;
	CONFIG_INIT(config);
	config_read(&config, CONFIG_FILE);

	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sighup_handler;
	sigaction(SIGHUP, &sa, NULL);

	self_pid = getpid();
	sprintf(self_name, "%d", self_pid);

	List list;
	LIST_INIT(list);

	while(1){
		sleep(1);

		if(sighup_coming){
			sighup_coming = 0;
			config_read(&config, CONFIG_FILE);
		}

		scan_proc_dir(&list, PROC_DIR, NULL, 0.5, &config);
		printf("process count: %zu\n", list.size);
	}

	// int tmpfd = open("/tmp/testfile", O_RDONLY | O_CREAT); // for testing systemctl
	return 0;
}
