#include "signal.h"

volatile sig_atomic_t sighup_coming = 0;

void sighup_handler(int signum){
	sighup_coming = 1;
}

void send_notification(Process *proc, int signum, const char *notification){
	FILE *tty_ptr = fopen(proc->tty_path, "w");
	if(!tty_ptr)
		return;

	fprintf(tty_ptr, "%s\n", notification);

	if(SIGSTOP == signum){
		fprintf(tty_ptr, "To resume the process, you could use 'jobs' command to check the jobID then use 'fg %%jobID' command\n");
		fprintf(tty_ptr, "To kill the process, you could use 'kill -s 9 %d' command\n", proc->pid);
	}

	fclose(tty_ptr);
}

int send_signal(Process *proc, int signum, const char *notification){
	if(notification)
		send_notification(proc, signum, notification);

	return kill(proc->pid, signum);
}
