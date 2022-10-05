#include "signal.h"

volatile sig_atomic_t sighup_coming = 0;

void sighup_handler(int signum){
	sighup_coming = 1;
}

int send_signal(pid_t pid, int signum){
	return kill(pid, signum);
}
