#ifndef SIGNAL_HDR
#define SIGNAL_HDR

#include "basis.h"
#include "process.h"

volatile sig_atomic_t sighup_coming;

void sighup_handler(int signum);

int send_signal(Process *proc, int signum, const char *notification);

#endif
