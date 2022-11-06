#include "signal.h"

volatile sig_atomic_t sighup_coming = 0;

void sighup_handler(int signum){
	sighup_coming = 1;
}

void send_notification(Process *proc, const char *notification){
	char pid[32] = {0};
        sprintf(pid, "%d", proc->pid);

        char fd0_path[32] = {0};
        strcpy(fd0_path, PROC_DIR);
        strcat(fd0_path, "/");
        strcat(fd0_path, pid);
        strcat(fd0_path, "/");
        strcat(fd0_path, "fd");
        strcat(fd0_path, "/");
        strcat(fd0_path, "0");

	int fd0;
	fd0 = open(fd0_path, O_WRONLY);
	write(fd0, notification, strlen(notification));
	close(fd0);
}

int send_signal(Process *proc, int signum, const char *notification){
	if(notification)
		send_notification(proc, notification);
	return kill(proc->pid, signum);
}
