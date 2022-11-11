#include "basis.h"
#include <syslog.h>
#include <stdarg.h>

void log_open(void){
	openlog(NULL, LOG_ODELAY | LOG_PID, LOG_USER);
}

void log_close(void){
	closelog();
}
