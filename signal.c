#include "signal.h"

volatile sig_atomic_t sighup_coming = 0;

void sighup_handler(int signum){
	sighup_coming = 1;
}

void send_notification(Process *proc, const char *notification){
	int tty_fd;
	tty_fd = open(proc->tty_path, O_WRONLY);
	if(-1 == tty_fd)
		return;
	write(tty_fd, notification, strlen(notification));
	close(tty_fd);
}

int send_signal(Process *proc, int signum, const char *notification){
	if(notification)
		send_notification(proc, notification);
	return kill(proc->pid, signum);
}
