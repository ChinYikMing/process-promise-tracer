#ifndef SIGNAL_HDR
#define SIGNAL_HDR

#include "basis.h"

volatile sig_atomic_t sighup_coming;

void sighup_handler(int signum);

#endif
