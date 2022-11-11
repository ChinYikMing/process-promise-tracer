#ifndef LOG_HDR
#define LOG_HDR

#include "basis.h"
#include <syslog.h>

#define LOG_PREFIX "(Process Promise Tracer msg): "

void log_open(void);
void log_close(void);

/*
 * usage:
 * 	any log message must be write with below method:
 * 	log_open();
 * 	syslog(priority, LOG_PREFIX"formatted message here"[, arguments]); 
 * 	log_close();
 *
 * 	priority could be:
 * 		1. LOG_ALERT, when something emergency, e.g., detected data leaked
 * 		2. LOG_ERR, when errors occur, e.g., run out of memory
 * 		3. LOG_NOTICE, when something have to be recorded, e.g., detected a new process
 *
 *      arguments are optional depends on format of message
 *      
 *      For usage example, you could refer to process-promise-tracerd.c
 */

#endif
